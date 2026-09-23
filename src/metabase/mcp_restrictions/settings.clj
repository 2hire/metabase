(ns metabase.mcp-restrictions.settings
  (:require
   [metabase.settings.core :as setting :refer [defsetting]]
   [metabase.util.i18n :refer [deferred-tru]]))

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
