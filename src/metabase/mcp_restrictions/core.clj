(ns metabase.mcp-restrictions.core
  "Admin-configured limits on AI clients: who may use the MCP server (see [[user-allowed?]]), and which databases and
  tables are off-limits to them.

  The restriction only applies while [[*enforced?*]] is bound to true, which the AI entry points do for the lifetime of
  a request: the MCP server and the Agent API it dispatches to, OAuth bearer tokens issued to MCP clients, and the
  scoped credential used by the MCP Apps visualization iframe. The regular Metabase UI is never affected. When
  enforced, the restriction applies to every user, admins included.

  Enforcement points:
  - the query processor permissions middleware rejects any query that reads a restricted database or table
    (see [[check-query-allowed!]]);
  - `mi/can-read?` for Tables and Databases returns false, which hides them from navigation and metadata lookups;
  - AI search results drop restricted tables and the Cards built on them."
  (:require
   [clojure.string :as str]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.util.i18n :refer [tru]]
   [toucan2.core :as t2])
  (:import
   (java.util.regex Pattern)))

(set! *warn-on-reflection* true)

(def ^:dynamic *enforced?*
  "Whether the current request comes from an AI client and must respect the MCP data restrictions. Bind it with
  [[with-restrictions-enforced]]; never read it directly outside this namespace."
  false)

(defmacro with-restrictions-enforced
  "Run `body` with the MCP data restrictions enforced."
  [& body]
  `(binding [*enforced?* true]
     ~@body))

(defn enforced?
  "Whether the MCP data restrictions apply to the current request."
  []
  *enforced?*)

(defn- restricted-database-ids [] (set (mcp-restrictions.settings/mcp-restricted-database-ids)))

(defn- restricted-table-ids [] (set (mcp-restrictions.settings/mcp-restricted-table-ids)))

(defn restricted-database?
  "Whether the database with `database-id` is off-limits for the current request."
  [database-id]
  (boolean
   (and *enforced?*
        database-id
        (contains? (restricted-database-ids) database-id))))

(defn restricted-table?
  "Whether the table with `table-id` in the database with `database-id` is off-limits for the current request. A table
  is restricted when it is listed itself or when its database is."
  [database-id table-id]
  (boolean
   (and *enforced?*
        (or (restricted-database? database-id)
            (and table-id (contains? (restricted-table-ids) table-id))))))

(defn restriction-exception
  "The exception thrown when an AI client tries to reach restricted data."
  []
  (ex-info (tru "This data is not available to MCP clients.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn check-table-allowed!
  "Throw a 403 if the table is off-limits for the current request."
  [database-id table-id]
  (when (restricted-table? database-id table-id)
    (throw (restriction-exception))))

(defn- table-name-pattern
  "Case-insensitive pattern matching `table-name` as a whole SQL identifier, quoted or not."
  ^Pattern [table-name]
  (re-pattern (str "(?i)(?<![\\p{L}\\p{N}_$])" (Pattern/quote table-name) "(?![\\p{L}\\p{N}_$])")))

(defn- sql-references-table?
  "Conservative check for a native query naming a table: any mention of the table name as a standalone identifier
  counts, so false positives (a column or a string literal with the same name) block the query rather than leak data.
  A SQL parser would be more precise but returns nothing when it cannot parse a statement, which fails open."
  [sql table-name]
  (and (not (str/blank? table-name))
       (boolean (re-find (table-name-pattern table-name) sql))))

(defn check-native-sql-allowed!
  "Throw a 403 if any of the `sqls` native query strings run against `database-id` names a restricted table."
  [database-id sqls]
  (when (and *enforced?* database-id (seq sqls))
    (when-let [table-ids (not-empty (restricted-table-ids))]
      (let [table-names (t2/select-fn-set :name :model/Table :db_id database-id :id [:in table-ids])]
        (when (some (fn [sql] (some #(sql-references-table? sql %) table-names)) sqls)
          (throw (restriction-exception)))))))

(defn check-query-allowed!
  "Throw a 403 if a query against `database-id` that reads `table-ids` and runs the native `sqls` touches restricted
  data. No-op unless the restrictions are enforced for the current request."
  [database-id table-ids sqls]
  (when *enforced?*
    (when (restricted-database? database-id)
      (throw (restriction-exception)))
    (when-let [restricted (not-empty (restricted-table-ids))]
      (when (some restricted table-ids)
        (throw (restriction-exception)))
      (check-native-sql-allowed! database-id sqls))))

(def ^:private card-search-types #{"question" "model" "metric"})

(defn remove-restricted-search-results
  "Remove search results that point at restricted data: tables that are restricted themselves, anything in a
  restricted database, and Cards whose source table is restricted."
  [results]
  (if-not (and *enforced?* (or (seq (restricted-database-ids)) (seq (restricted-table-ids))))
    results
    (let [card-ids      (into #{}
                              (keep #(when (card-search-types (some-> (:type %) name)) (:id %)))
                              results)
          card->table   (when (seq card-ids)
                          (t2/select-pk->fn :table_id :model/Card :id [:in card-ids]))
          restricted?   (fn [{:keys [id type database_id]}]
                          (let [type (some-> type name)]
                            (or (restricted-database? database_id)
                                (and (= type "table") (restricted-table? database_id id))
                                (and (card-search-types type)
                                     (restricted-table? database_id (get card->table id))))))]
      (into [] (remove restricted?) results))))

;;; ------------------------------------------------- Access list --------------------------------------------------

(defn user-allowed?
  "Whether the user with `user-id` may use the MCP server and the Agent API. Admins always may. Everyone may while the
  access list is empty; once it names users or groups, only those users and members of those groups may."
  [user-id]
  (let [allowed-user-ids  (set (mcp-restrictions.settings/mcp-allowed-user-ids))
        allowed-group-ids (set (mcp-restrictions.settings/mcp-allowed-group-ids))]
    (boolean
     (or (and (empty? allowed-user-ids) (empty? allowed-group-ids))
         (and user-id
              (or (contains? allowed-user-ids user-id)
                  (t2/select-one-fn :is_superuser :model/User :id user-id)
                  (and (seq allowed-group-ids)
                       (t2/exists? :model/PermissionsGroupMembership
                                   :user_id  user-id
                                   :group_id [:in allowed-group-ids]))))))))

(defn access-denied-message
  "The message shown to a user who is not on the MCP access list."
  []
  (tru "You are not allowed to use the MCP server. Ask an admin to add you to the MCP access list."))
