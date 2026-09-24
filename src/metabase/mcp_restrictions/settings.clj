(ns metabase.mcp-restrictions.settings
  (:require
   [clojure.string :as str]
   [metabase.settings.core :as setting :refer [defsetting]]
   [metabase.util.i18n :refer [deferred-tru tru]]))

(set! *warn-on-reflection* true)

(defn- normalize-ids
  "Coerce a setting value to a sorted vector of distinct positive integer IDs."
  [ids]
  (->> ids
       (keep #(cond
                (int? %)    %
                (string? %) (parse-long %)))
       (filter pos?)
       distinct
       sort
       vec))

(defsetting mcp-restricted-database-ids
  (deferred-tru "IDs of databases that MCP clients cannot see or query, admins included.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-restricted-database-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-restricted-database-ids (some-> % normalize-ids)))

(defsetting mcp-restricted-table-ids
  (deferred-tru "IDs of tables that MCP clients cannot see or query, admins included.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-restricted-table-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-restricted-table-ids (some-> % normalize-ids)))

(defsetting mcp-allowed-user-ids
  (deferred-tru "IDs of users allowed to use the MCP server. When this and the allowed groups are both empty, everyone can.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-allowed-user-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-allowed-user-ids (some-> % normalize-ids)))

(defsetting mcp-allowed-group-ids
  (deferred-tru "IDs of groups whose members are allowed to use the MCP server. When this and the allowed users are both empty, everyone can.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-allowed-group-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-allowed-group-ids (some-> % normalize-ids)))

(defsetting mcp-sensitive-fields-auto-detect
  (deferred-tru "Whether fields whose name looks like a secret (password, token, API key...) are treated as sensitive for MCP clients.")
  :type       :boolean
  :default    true
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false)

(defsetting mcp-sensitive-field-ids
  (deferred-tru "IDs of fields whose values MCP clients can't see, in addition to the automatically detected ones.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-sensitive-field-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-sensitive-field-ids (some-> % normalize-ids)))

(defsetting mcp-non-sensitive-field-ids
  (deferred-tru "IDs of fields never treated as sensitive for MCP clients, even when their name looks like a secret.")
  :type       :json
  :encryption :no
  :default    []
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :getter     #(normalize-ids (setting/get-value-of-type :json :mcp-non-sensitive-field-ids))
  :setter     #(setting/set-value-of-type! :json :mcp-non-sensitive-field-ids (some-> % normalize-ids)))

(defsetting mcp-audit-log-enabled?
  (deferred-tru "Whether the requests made by MCP clients are recorded in the MCP audit log.")
  :type       :boolean
  :default    true
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false)

(defn- parse-retention-days
  "The number of days `new-value` (an integer, or a string holding one) stands for, or nil to reset the setting to its
  default. Throws a 400 for anything else: silently falling back to the default would make the retention job delete
  entries the admin meant to keep."
  [new-value]
  (let [days (cond
               (nil? new-value)    nil
               (integer? new-value) new-value
               (and (number? new-value) (== new-value (Math/floor (double new-value)))) (long new-value)
               (and (string? new-value) (re-matches #"\s*\d+\s*" new-value)) (or (parse-long (str/trim new-value)) ::invalid)
               :else ::invalid)]
    (when (or (= days ::invalid) (and days (neg? days)))
      (throw (ex-info (tru "The MCP audit log retention must be a whole number of days, zero or more.")
                      {:status-code 400})))
    days))

(defsetting mcp-audit-log-retention-days
  (deferred-tru "How many days MCP audit log entries are kept before they are deleted. Set it to 0 to keep them forever.")
  :type       :integer
  :default    90
  :visibility :admin
  :export?    false
  :audit      :getter
  :doc        false
  :setter     (fn [new-value]
                (setting/set-value-of-type! :integer :mcp-audit-log-retention-days (parse-retention-days new-value))))
