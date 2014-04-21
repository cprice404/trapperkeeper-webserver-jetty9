(ns puppetlabs.trapperkeeper.services.webserver.jetty9-core
  (:import (org.eclipse.jetty.server Handler Server Request ServerConnector
                                     HttpConfiguration HttpConnectionFactory
                                     ConnectionFactory)
           (org.eclipse.jetty.server.handler AbstractHandler ContextHandler HandlerCollection ContextHandlerCollection)
           (org.eclipse.jetty.util.resource Resource)
           (org.eclipse.jetty.util.thread QueuedThreadPool)
           (org.eclipse.jetty.util.ssl SslContextFactory)
           (javax.servlet.http HttpServletRequest HttpServletResponse)
           (java.util.concurrent Executors)
           (org.eclipse.jetty.servlets.gzip GzipHandler)
           (org.eclipse.jetty.servlet ServletContextHandler ServletHolder DefaultServlet)
           (org.eclipse.jetty.webapp WebAppContext)
           (java.util HashSet)
           (org.eclipse.jetty.http MimeTypes)
           (javax.servlet Servlet ServletContextListener)
           (java.io File)
           (org.eclipse.jetty.proxy ProxyServlet)
           (java.net URI)
           (java.security Security)
           (org.eclipse.jetty.client HttpClient))
  (:require [ring.util.servlet :as servlet]
            [clojure.string :as str]
            [clojure.set :as set]
            [clojure.tools.logging :as log]
            [schema.macros :as sm]
            [puppetlabs.kitchensink.core :as ks]
            [puppetlabs.trapperkeeper.services.webserver.jetty9-config :as config]
            [schema.core :as schema]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; JDK SecurityProvider Hack

;; Work around an issue with OpenJDK's PKCS11 implementation preventing TLSv1
;; connections from working correctly
;;
;; http://stackoverflow.com/questions/9586162/openjdk-and-php-ssl-connection-fails
;; https://bugs.launchpad.net/ubuntu/+source/openjdk-6/+bug/948875
(if (re-find #"OpenJDK" (System/getProperty "java.vm.name"))
  (try
    (let [klass     (Class/forName "sun.security.pkcs11.SunPKCS11")
          blacklist (filter #(instance? klass %) (Security/getProviders))]
      (doseq [provider blacklist]
        (log/info (str "Removing buggy security provider " provider))
        (Security/removeProvider (.getName provider))))
    (catch ClassNotFoundException e)
    (catch Throwable e
      (log/error e "Could not remove security providers; HTTPS may not work!"))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schemas

(def ProxyOptions
  {(schema/optional-key :scheme) (schema/enum :orig :http :https)
   (schema/optional-key :ssl-config) (schema/either
                                       (schema/eq :use-server-config)
                                       config/WebserverSslPemConfig)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility Functions

(defn- remove-leading-slash
  [s]
  (str/replace s #"^\/" ""))

; TODO :-
(defn has-state?
  "A predicate that indicates whether or not the webserver-context contains a
  ':state' map, used for capturing any configuration settings that can be
  atomically updated at run-time."
  [webserver-context]
  (and
    (map? webserver-context)
    (contains? webserver-context :state)
    (map? @(:state webserver-context))))

; TODO :-
(defn has-handlers?
  "A predicate that indicates whether or not the webserver-context contains a
  ContextHandlerCollection which can have handlers attached to it."
  [webserver-context]
  (and
    (map? webserver-context)
    (instance? ContextHandlerCollection (:handlers webserver-context))))

; TODO :-
(defn has-webserver?
  "A predicate that indicates whether or not the webserver-context contains a Jetty
  Server object."
  [webserver-context]
  (and
    (has-handlers? webserver-context)
    (instance? Server (:server webserver-context))))

; TODO :-
(defn proxy-target?
  "A predicate that validates the format of a proxy target configuration map"
  [target]
  ;; TODO: should probably be using prismatic schema here (PE-3409)
  (and
    (map? target)
    (string? (:host target))
    (string? (:path target))
    (integer? (:port target))
    (> (:port target) 0)
    (<= (:port target) 65535)))

(defn- ring-handler
  "Returns an Jetty Handler implementation for the given Ring handler."
  [handler]
  (proxy [AbstractHandler] []
    (handle [_ ^Request base-request request response]
      (let [request-map  (servlet/build-request-map request)
            response-map (handler request-map)]
        (when response-map
          (servlet/update-servlet-response response response-map)
          (.setHandled base-request true))))))

; TODO: move
(sm/defn ^:always-validate
  ssl-context-factory  ; :- TODO
  "Creates a new SslContextFactory instance from a map of options."
  [config :- config/WebserverSslKeystoreConfig
   client-auth :- config/WebserverSslClientAuth]
  (let [context (SslContextFactory.)]
    (.setKeyStore context (:keystore config))
    (.setKeyStorePassword context (:key-password config))
    (.setTrustStore context (:truststore config))
    (when-let [trust-password (:trust-password config)]
      (.setTrustStorePassword context trust-password))
    (case client-auth
      :need (.setNeedClientAuth context true)
      :want (.setWantClientAuth context true)
      nil)
    context))

; TODO move to a better section of the file
(sm/defn ^:always-validate
  get-proxy-client-context-factory :- SslContextFactory
  [ssl-config :- config/WebserverSslPemConfig]
  (-> ssl-config
      config/pem-ssl-config->keystore-ssl-config
      (ssl-context-factory :none)))

(defn- connection-factory
  []
  (let [http-config (doto (HttpConfiguration.)
                      (.setSendDateHeader true))]
    (into-array ConnectionFactory
                [(HttpConnectionFactory. http-config)])))

(sm/defn ^:always-validate
  ssl-connector  ; :- TODO
  "Creates a ssl ServerConnector instance."
  [server            ; :- TODO
   ssl-ctxt-factory  ; :- TODO
   config :- config/WebserverSslConnector]
  (doto (ServerConnector. server ssl-ctxt-factory (connection-factory))
    (.setPort (:port config))
    (.setHost (:host config))))

(sm/defn ^:always-validate
  plaintext-connector ; :- TODO
  [server ; :- TODO
   config :- config/WebserverConnector]
  (doto (ServerConnector. server (connection-factory))
    (.setPort (:port config))
    (.setHost (:host config))))

;; TODO: make all of this gzip-mime-type stuff configurable
(defn- gzip-excluded-mime-types
  "Build up a list of mime types that should not be candidates for
  gzip compression in responses."
  []
  (->
    ;; This code is ported from Jetty 9.0.5's GzipFilter class.  In
    ;; Jetty 7, this behavior was the default for GzipHandler as well
    ;; as GzipFilter, but in Jetty 9.0.5 the GzipHandler no longer
    ;; includes this, so we need to do it by hand.
    (filter #(or (.startsWith % "image/")
                 (.startsWith % "audio/")
                 (.startsWith % "video/"))
            (MimeTypes/getKnownMimeTypes))
    (conj "application/compress" "application/zip" "application/gzip" "text/event-stream")
    (HashSet.)))

(defn- gzip-handler
  "Given a handler, wrap it with a GzipHandler that will compress the response
  when appropriate."
  [handler]
  (doto (GzipHandler.)
    (.setHandler handler)
    (.setMimeTypes (gzip-excluded-mime-types))
    (.setExcludeMimeTypes true)))

; TODO :-
(sm/defn ^:always-validate
  proxy-servlet :- ProxyServlet
  "Create an instance of Jetty's `ProxyServlet` that will proxy requests at
  a given context to another host."
  [webserver-context ; TODO :-
   target ; TODO :-
   options :- ProxyOptions]
  {:pre [(has-state? webserver-context)
         (has-handlers? webserver-context)
         (proxy-target? target)]}
  (let [custom-ssl-ctxt-factory (when (map? (:ssl-config options))
                                  (get-proxy-client-context-factory (:ssl-config options)))]
    (proxy [ProxyServlet] []
      (rewriteURI [req]
        (let [query (.getQueryString req)
              scheme (let [target-scheme (:scheme options)]
                       (condp = target-scheme
                         nil (.getScheme req)
                         :orig (.getScheme req)
                         :http "http"
                         :https "https"))
              context-path (.getPathInfo req)
              uri (str scheme "://" (:host target) ":" (:port target)
                       "/" (:path target) context-path)]
          (when query
            (.append uri "?")
            (.append uri query))
          (URI/create (.toString uri))))

      (newHttpClient []
        (if custom-ssl-ctxt-factory
          (HttpClient. custom-ssl-ctxt-factory)
          (if-let [ssl-ctxt-factory (:ssl-context-factory @(:state webserver-context))]
            (HttpClient. ssl-ctxt-factory)
            (HttpClient.)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(sm/defn ^:always-validate
  create-server ; :- TODO
  "Construct a Jetty Server instance."
  [webserver-context ; :- TODO
   config :- config/WebserverServiceConfig]
  (let [server (Server. (QueuedThreadPool. (:max-threads config)))]
    (when (:http config)
      (let [connector (plaintext-connector server (:http config))]
        (.addConnector server connector)))
    (when-let [https (:https config)]
      (let [ssl-ctxt-factory (ssl-context-factory
                               (:keystore-config https)
                               (:client-auth https))
            connector (ssl-connector server ssl-ctxt-factory https)]
        (when-let [ciphers (:cipher-suites https)]
          (.setIncludeCipherSuites ssl-ctxt-factory (into-array ciphers)))
        (when-let [protocols (:protocols https)]
          (.setIncludeProtocols ssl-ctxt-factory (into-array protocols)))
        (.addConnector server connector)
        (swap! (:state webserver-context) assoc :ssl-context-factory ssl-ctxt-factory)))
    server))

; TODO :- and move out of public
(defn- merge-webserver-overrides-with-options
  "Merge any overrides made to the webserver config settings with the supplied
   options."
  [options webserver-context]
  {:pre  [(has-state? webserver-context)]
   :post [(map? %)]}
  (let [overrides (:overrides (swap! (:state webserver-context)
                                     assoc
                                     :overrides-read-by-webserver
                                     true))]
    (doseq [key (keys overrides)]
      (log/info (str "webserver config overridden for key '" (name key) "'")))
    (merge options overrides)))

(sm/defn ^:always-validate
  create-webserver ;:- TODO WebserverContext
    "Create a Jetty webserver according to the supplied options:

    :host         - the hostname to listen on
    :port         - the port to listen on (defaults to 8080)
    :ssl-host     - the hostname to listen on for SSL connections
    :ssl-port     - the SSL port to listen on (defaults to 8081)
    :max-threads  - the maximum number of threads to use (default 100)

    SSL may be configured via PEM files by providing all three of the following
    settings:

    :ssl-key      - a PEM file containing the host's private key
    :ssl-cert     - a PEM file containing the host's certificate
    :ssl-ca-cert  - a PEM file containing the CA certificate

    or via JKS keystore files by providing all four of the following settings:

    :keystore       - the keystore to use for SSL connections
    :key-password   - the password to the keystore
    :truststore     - a truststore to use for SSL connections
    :trust-password - the password to the truststore

    Other SSL settings:

    :client-auth   - SSL client certificate authenticate, may be set to :need,
                     :want or :none (defaults to :need)
    :cipher-suites - list of cryptographic ciphers to allow for incoming SSL connections
    :ssl-protocols - list of protocols to allow for incoming SSL connections"
  [options :- config/WebserverServiceRawConfig
   webserver-context]
  {:pre [(map? options)
         (has-state? webserver-context)
         (has-handlers? webserver-context)]
   :post [(has-webserver? %)]}
    (let [config                (config/process-config
                                  (merge-webserver-overrides-with-options
                                    options
                                    webserver-context))
          ^Server s             (create-server webserver-context config)
          ^HandlerCollection hc (HandlerCollection.)]
    (.setHandlers hc (into-array Handler [(:handlers webserver-context)]))
    (.setHandler s (gzip-handler hc))
    (assoc webserver-context :server s)))

; TODO :-
(defn create-handlers
  "Create a webserver-context which contains a HandlerCollection and a
  ContextHandlerCollection which can accept the addition of new handlers
  before the webserver is started."
  []
  {:post [(has-handlers? %)]}
  (let [^ContextHandlerCollection chc (ContextHandlerCollection.)]
    {:handlers chc
     :state (atom {})}))

; TODO :-
(defn start-webserver
  "Starts a webserver that has been previously created and added to the
  webserver-context by `create-webserver`"
  [webserver-context]
  {:pre [(has-webserver? webserver-context)]}
  (.start (:server webserver-context)))

; TODO :-
(defn add-handler
  [webserver-context handler]
  {:pre [(has-handlers? webserver-context)
         (instance? ContextHandler handler)]}
  (.addHandler (:handlers webserver-context) handler)
  handler)

; TODO :-
(defn add-context-handler
  "Add a static content context handler (allow for customization of the context handler through javax.servlet.ServletContextListener implementations)"
  ([webserver-context base-path context-path]
   (add-context-handler webserver-context base-path context-path nil))
  ([webserver-context base-path context-path context-listeners]
   {:pre [(has-handlers? webserver-context)
          (string? base-path)
          (string? context-path)
          (or (nil? context-listeners)
              (and (sequential? context-listeners)
                   (every? #(instance? ServletContextListener %) context-listeners)))]}
   (let [handler (ServletContextHandler. nil context-path ServletContextHandler/NO_SESSIONS)]
     (.setBaseResource handler (Resource/newResource base-path))
     ;; register servlet context listeners (if any)
     (when-not (nil? context-listeners)
       (dorun (map #(.addEventListener handler %) context-listeners)))
     (.addServlet handler (ServletHolder. (DefaultServlet.)) "/")
     (add-handler webserver-context handler))))

; TODO :-
(defn add-ring-handler
  [webserver-context handler path]
  {:pre [(has-handlers? webserver-context)
         (ifn? handler)
         (string? path)]}
  (let [ctxt-handler (doto (ContextHandler. path)
                       (.setHandler (ring-handler handler)))]
    (add-handler webserver-context ctxt-handler)))

; TODO :-
(defn add-servlet-handler
  ([webserver-context servlet path]
   (add-servlet-handler webserver-context servlet path {}))
  ([webserver-context servlet path servlet-init-params]
   {:pre [(has-handlers? webserver-context)
          (instance? Servlet servlet)
          (string? path)
          (map? servlet-init-params)]}
   (let [holder   (doto (ServletHolder. servlet)
                    (.setInitParameters servlet-init-params))
         handler  (doto (ServletContextHandler. ServletContextHandler/SESSIONS)
                    (.setContextPath path)
                    (.addServlet holder "/*"))]
     (add-handler webserver-context handler))))

; TODO :-
(defn add-war-handler
  "Registers a WAR to Jetty. It takes two arguments: `[war path]`.
  - `war` is the file path or the URL to a WAR file
  - `path` is the URL prefix at which the WAR will be registered"
  [webserver-context war path]
  {:pre [(has-handlers? webserver-context)
         (string? war)
         (string? path)]}
  (let [handler (doto (WebAppContext.)
                  (.setContextPath path)
                  (.setWar war))]
    (add-handler webserver-context handler)))

; TODO :-
(sm/defn ^:always-validate
  add-proxy-route
  "Configures the Jetty server to proxy a given URL path to another host.

  `target` should be a map containing the keys :host, :port, and :path; where
  :path specifies the URL prefix to proxy to on the target host.

  `options` may contain the keys :scheme (legal values are :orig, :http, and :https)
  and :ssl-config (value may be :use-server-config or a map containing :ssl-ca-cert,
  :ssl-cert, and :ssl-key).
  "
  [webserver-context ; TODO :-
   target ; TODO :-
   path ; TODO :-
   options :- ProxyOptions]
  {:pre [(has-handlers? webserver-context)
         (proxy-target? target)
         (string? path)]}
  (let [target (update-in target [:path] remove-leading-slash)]
    (add-servlet-handler webserver-context
                         (proxy-servlet webserver-context target options)
                         path)))

; TODO :-
(defn override-webserver-settings!
  "Override the settings in the webserver section of the service's config file
   with the set of options in the supplied overrides map.

   The map should contain a key/value pair for each setting to be overridden.
   The name of the setting to override should be expressed as a Clojure keyword.
   For any setting expressed in the service config which is not overridden, the
   setting value from the config will be used.

   For example, the webserver config may contain:

     [webserver]
     ssl-host    = 0.0.0.0
     ssl-port    = 9001
     ssl-cert    = mycert.pem
     ssl-key     = mykey.pem
     ssl-ca-cert = myca.pem

   The following overrides map may be supplied as an argument to the function:

     {:ssl-port 9002
      :ssl-cert \"myoverriddencert.pem\"
      :ssl-key  \"myoverriddenkey.pem\"}

   The effective settings used during webserver startup will be:

     {:ssl-host    \"0.0.0.0\"
      :ssl-port    9002
      :ssl-cert    \"myoverriddencert.pem\"
      :ssl-key     \"myoverriddenkey.pem\"
      :ssl-ca-cert \"myca.pem\"}

   The overridden webserver settings will be considered only at the point the
   webserver is being started -- during the start lifecycle phase of the
   webserver service.  For this reason, a call to this function must be made
   during a service's init lifecycle phase in order for the overridden
   settings to be considered.

   Only one call from a service may be made to this function during application
   startup.

   If a call is made to this function after webserver startup or after another
   call has already been made to this function (e.g., from other service),
   a java.lang.IllegalStateException will be thrown."
  [webserver-context overrides]
  {:pre  [(has-state? webserver-context)
          (map? overrides)]
   :post [(map? %)]}
  ; Might be worth considering an implementation that only fails if the caller
  ; is trying to override a specific option that has been overridden already
  ; rather than blindly failing if an attempt is made to override any option.
  ; Could allow different services to override options that don't conflict with
  ; one another or for the same service to make multiple calls to this function
  ; for different settings.  Hard to know, though, when one setting has an
  ; adverse effect on another without putting a bunch of key-specific semantic
  ; setting parsing in this implementation.
  (:overrides
    (swap! (:state webserver-context)
           #(cond
             (:overrides-read-by-webserver %)
               (if (nil? (:overrides %))
                 (throw
                   (IllegalStateException.
                     (str "overrides cannot be set because webserver has "
                          "already processed the config")))
                 (throw
                   (IllegalStateException.
                     (str "overrides cannot be set because they have "
                          "already been set and webserver has already "
                          "processed the config"))))
             (nil? (:overrides %))
               (assoc % :overrides overrides)
             :else
               (throw
                 (IllegalStateException.
                   (str "overrides cannot be set because they have "
                        "already been set")))))))

; TODO :-
(defn join
  [webserver-context]
  {:pre [(has-webserver? webserver-context)]}
  (.join (:server webserver-context)))

; TODO :-
(defn shutdown
  [webserver-context]
  {:pre [(has-webserver? webserver-context)]}
  (log/info "Shutting down web server.")
  (.stop (:server webserver-context)))

