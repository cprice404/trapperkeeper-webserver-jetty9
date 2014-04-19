(ns puppetlabs.trapperkeeper.services.webserver.jetty9-config
  (:import [java.security KeyStore])
  (:require [clojure.tools.logging :as log]
            [schema.core :as schema]
            [schema.macros :as sm]
            [puppetlabs.certificate-authority.core :as ssl]
            [puppetlabs.kitchensink.core :refer [missing? num-cpus uuid]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schemas

(def WebserverServiceRawConfig {(schema/optional-key :port) schema/Int})

(def WebserverConnector {:host schema/Str :port schema/Int})

(def WebserverConnectors (schema/either
                           {:http WebserverConnector}
                           {:https WebserverConnector}
                           {:http WebserverConnector
                            :https WebserverConnector}))

(def WebserverServiceConfig {:connectors WebserverConnectors})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(sm/defn ^:always-validate process-config :- WebserverServiceConfig
  [config :- WebserverServiceRawConfig]
  config)

(defn configure-web-server-ssl-from-pems
  "Configures the web server's SSL settings based on PEM files, rather than
  via a java keystore (jks) file.  The configuration map returned by this function
  will have overwritten any existing keystore-related settings to use in-memory
  KeyStore objects, which are constructed based on the values of
  `:ssl-key`, `:ssl-cert`, and `:ssl-ca-cert` from
  the input map.  The output map does not include the `:ssl-*` keys, as they
  are not meaningful to the web server implementation."
  [{:keys [ssl-key ssl-cert ssl-ca-cert] :as options}]
  {:pre  [ssl-key
          ssl-cert
          ssl-ca-cert]
   :post [(map? %)
          (instance? KeyStore (:keystore %))
          (string? (:key-password %))
          (instance? KeyStore (:truststore %))
          (missing? % :trust-password :ssl-key :ssl-cert :ssl-ca-cert)]}
  (let [old-ssl-config-keys [:keystore :truststore :key-password :trust-password]
        old-ssl-config      (select-keys options old-ssl-config-keys)]
    (when (pos? (count old-ssl-config))
      (log/warn (format "Found settings for both keystore-based and PEM-based SSL; using PEM-based settings, ignoring %s"
                  (keys old-ssl-config)))))
  (let [truststore  (-> (ssl/keystore)
                      (ssl/assoc-certs-from-file! "CA Certificate" ssl-ca-cert))
        keystore-pw (uuid)
        keystore    (-> (ssl/keystore)
                      (ssl/assoc-private-key-file! "Private Key" ssl-key keystore-pw ssl-cert))]
    (-> options
      (dissoc :ssl-key :ssl-ca-cert :ssl-cert :trust-password)
      (assoc :keystore keystore)
      (assoc :key-password keystore-pw)
      (assoc :truststore truststore))))

(defn configure-web-server
  "Update the supplied config map with information about the HTTP webserver to
  start. This will specify client auth."
  [options]
  {:pre  [(map? options)]
   :post [(map? %)
          (missing? % :ssl-key :ssl-cert :ssl-ca-cert)
          (contains? % :max-threads)]}
  (if (missing? options :port :ssl-port)
    (throw (IllegalArgumentException.
             "Either port or ssl-port must be specified on the config in order for a port binding to be opened")))
  (let [defaults          {:max-threads 100}
        options           (merge defaults options)
        pem-required-keys [:ssl-key :ssl-cert :ssl-ca-cert]
        pem-config        (select-keys options pem-required-keys)]
    (-> (condp = (count pem-config)
          3 (configure-web-server-ssl-from-pems options)
          0 options
          (throw (IllegalArgumentException.
                   (format "Found SSL config options: %s; If configuring SSL from PEM files, you must provide all of the following options: %s"
                     (keys pem-config) pem-required-keys))))
      (assoc :client-auth
        (condp = (:client-auth options)
          "need" :need
          "want" :want
          "none" :none
          nil    :need
          (throw
            (IllegalArgumentException.
              (format
                "Unexpected value found for client auth config option: %s.  Expected need, want, or none."
                (:client-auth options)))))))))
