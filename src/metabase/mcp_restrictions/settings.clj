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
