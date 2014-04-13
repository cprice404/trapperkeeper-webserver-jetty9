(ns puppetlabs.trapperkeeper.services.webserver.jetty9-service
  (:require
    [clojure.tools.logging :as log]
    [puppetlabs.trapperkeeper.services.webserver.jetty9-core :as core]
    [puppetlabs.trapperkeeper.core :refer [defservice]]))


;; TODO: this should probably be moved to a separate jar that can be used as
;; a dependency for all webserver service implementations
(defprotocol WebserverService
  (add-context-handler [this base-path context-path] [this base-path context-path context-listeners])
  (add-context-handler-to [this server-id base-path context-path] [this server-id base-path context-path context-listeners])
  (add-ring-handler [this handler path])
  (add-ring-handler-to [this server-id handler path])
  (add-servlet-handler [this servlet path] [this servlet path servlet-init-params])
  (add-servlet-handler-to [this server-id servlet path] [this server-id servlet path servlet-init-params])
  (add-war-handler [this war path])
  (add-war-handler-to [this server-id war path])
  (add-proxy-route [this target path] [this target path options])
  (add-proxy-route-to [this server-id target path] [this server-id target path options])
  (override-webserver-settings! [this overrides])
  (override-webserver-settings-on! [this server-id overrides])
  (join [this]))

(defservice jetty9-service
  "Provides a Jetty 9 web server as a service"
  WebserverService
  [[:ConfigService get-in-config]]
  (init [this context]
        (log/info "Initializing web server.")
        (assoc context :jetty9-server (core/create-handlers)))

  (start [this context]
         (let [config (or (get-in-config [:webserver])
                          ;; Here for backward compatibility with existing projects
                          (get-in-config [:jetty])
                          {})
               webserver (core/create-webserver config (:jetty9-server context))]
           (log/info "Starting web server.")
           (core/start-webserver webserver)
           (assoc context :jetty9-server webserver)))

  (stop [this context]
        (log/info "Shutting down web server.")
        (core/shutdown (context :jetty9-server))
        context)

  (add-context-handler [this base-path context-path]
    (add-context-handler-to this :default base-path context-path))

  (add-context-handler [this base-path context-path context-listeners]
    (add-context-handler-to this :default base-path context-path context-listeners))

  (add-context-handler-to [this server-id base-path context-path]
                       (let [s ((service-context this) :jetty9-server)]
                         (core/add-context-handler s server-id base-path context-path)))

  (add-context-handler-to [this server-id base-path context-path context-listeners]
                       (let [s ((service-context this) :jetty9-server)]
                         (core/add-context-handler s server-id base-path context-path context-listeners)))

  (add-ring-handler [this handler path]
    (add-ring-handler-to this :default handler path))

  (add-ring-handler-to [this server-id handler path]
                    (let [s ((service-context this) :jetty9-server)]
                      (core/add-ring-handler s server-id handler path)))

  (add-servlet-handler [this servlet path]
    (add-servlet-handler-to this :default servlet path))

  (add-servlet-handler [this servlet path servlet-init-params]
    (add-servlet-handler-to this :default servlet path servlet-init-params))

  (add-servlet-handler-to [this server-id servlet path]
                       (let [s ((service-context this) :jetty9-server)]
                         (core/add-servlet-handler s server-id servlet path)))

  (add-servlet-handler-to [this server-id servlet path servlet-init-params]
                       (let [s ((service-context this) :jetty9-server)]
                         (core/add-servlet-handler s server-id servlet path servlet-init-params)))

  (add-war-handler [this war path]
    (add-war-handler-to this :default war path))

  (add-war-handler-to [this server-id war path]
                   (let [s ((service-context this) :jetty9-server)]
                     (core/add-war-handler s server-id war path)))

  (add-proxy-route [this target path]
    (add-proxy-route-to this :default target path))

  (add-proxy-route [this target path options]
    (add-proxy-route-to this :default target path options))

  (add-proxy-route-to [this server-id target path]
                   (let [s ((service-context this) :jetty9-server)]
                     (core/add-proxy-route s server-id target path {})))

  (add-proxy-route-to [this server-id target path options]
                   (let [s ((service-context this) :jetty9-server)]
                     (core/add-proxy-route s server-id target path options)))

  (override-webserver-settings! [this overrides]
    (override-webserver-settings-on! this :default overrides))

  (override-webserver-settings-on! [this server-id overrides]
                                (let [s ((service-context this) :jetty9-server)]
                                  (core/override-webserver-settings! s server-id overrides)))

  (join [this]
        (let [s ((service-context this) :jetty9-server)]
          (core/join s))))
