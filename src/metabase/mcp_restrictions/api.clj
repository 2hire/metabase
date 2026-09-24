(ns metabase.mcp-restrictions.api
  "`/api/mcp-restrictions/` routes."
  (:require
   [metabase.api.common :as api]
   [metabase.api.macros :as api.macros]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:private field-location-schema
  [:map
   [:id            pos-int?]
   [:name          :string]
   [:table_id      pos-int?]
   [:table_name    [:maybe :string]]
   [:schema        [:maybe :string]]
   [:database_id   [:maybe pos-int?]]
   [:database_name [:maybe :string]]])

(defn- with-locations
  "Add the table, schema and database names to `fields` (`{:id :name :table_id}` maps), sorted by location."
  [fields]
  (let [tables    (when (seq fields)
                    (t2/select-pk->fn identity [:model/Table :id :name :schema :db_id]
                                      :id [:in (into #{} (map :table_id) fields)]))
        databases (when (seq tables)
                    (t2/select-pk->fn :name :model/Database :id [:in (into #{} (map :db_id) (vals tables))]))]
    (->> fields
         (map (fn [{:keys [table_id] :as field}]
                (let [{table-name :name :keys [schema db_id]} (get tables table_id)]
                  (assoc (into {} field)
                         :table_name    table-name
                         :schema        schema
                         :database_id   db_id
                         :database_name (get databases db_id)))))
         (sort-by (juxt :database_name :schema :table_name :name))
         vec)))

(api.macros/defendpoint :get "/sensitive-fields"
  :- [:map
      [:sensitive [:sequential [:merge field-location-schema
                                [:map [:source [:enum "detected" "manual" "metadata"]]]]]]
      [:excluded  [:sequential field-location-schema]]]
  "Fields whose values MCP clients can't see, with where they live and why: added by an admin (`manual`), marked
  sensitive in the table metadata (`metadata`), or detected by name (`detected`). Also returns the fields an admin
  excluded, which are never treated as sensitive."
  []
  (api/check-superuser)
  (let [excluded-ids (mcp-restrictions.settings/mcp-non-sensitive-field-ids)]
    {:sensitive (->> (mcp-restrictions/sensitive-fields)
                     (map #(update % :source name))
                     with-locations)
     :excluded  (with-locations
                  (when (seq excluded-ids)
                    (t2/select [:model/Field :id :name :table_id] :id [:in excluded-ids])))}))
