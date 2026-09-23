(ns metabase.mcp-restrictions.core
  "Admin-configured limits on AI clients: who may use the MCP server (see [[user-allowed?]]), which databases and
  tables are off-limits to them, and which fields hold secrets they must never see (see [[sensitive-fields]]).

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
   [medley.core :as m]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.util :as u]
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

;;; ----------------------------------------------- Sensitive fields -----------------------------------------------

(def masked-value
  "What MCP clients see in place of a sensitive value."
  "••••")

(def ^:private secret-name-words
  "Words that make a field name look like a secret, compared against single name segments and adjacent pairs (so
  `api_key`, `apiKey` and `APIKEY` all match `apikey`)."
  #{"password" "passwd" "pwd" "passphrase" "secret" "token" "apikey" "privatekey" "accesskey" "secretkey"
    "credential" "credentials" "salt" "otp"})

(def ^:private metadata-name-suffixes
  "Last name segments that describe a secret rather than hold it: `token_type`, `password_changed_at`, `api_key_id`."
  #{"at" "on" "type" "id" "ids" "count" "expires" "expiry" "expiration" "date" "time" "ts" "timestamp" "length" "len"
    "enabled" "required" "set" "hint" "version" "updated" "created" "changed" "status" "name" "url" "uri" "scope"
    "scopes"})

(defn- name-segments
  "Split a column name into lower-case words on non-alphanumerics and camelCase boundaries."
  [column-name]
  (->> (str/split (str column-name) #"[^\p{L}\p{N}]+|(?<=\p{Ll})(?=\p{Lu})")
       (remove str/blank?)
       (map u/lower-case-en)))

(defn sensitive-field-name?
  "Whether a field called `field-name` looks like it holds a secret. `client_secret`, `access_token` and `password`
  do; `client_id`, `token_type` and `password_changed_at` don't."
  [field-name]
  (let [segments (vec (name-segments field-name))
        words    (concat segments (map str segments (rest segments)))]
    (boolean
     (and (seq segments)
          (not (metadata-name-suffixes (peek segments)))
          (some secret-name-words words)))))

(def ^:private secret-name-like-patterns
  "SQL `LIKE` patterns that pre-filter candidate field names in the app DB before [[sensitive-field-name?]] decides."
  ["%pass%" "%pwd%" "%secret%" "%token%" "%key%" "%credential%" "%salt%" "%otp%"])

(defn- in-database-clause
  "Where clause limiting fields to those of `database-id`, or nil for every database."
  [database-id]
  (when database-id
    (if-let [table-ids (not-empty (t2/select-pks-set :model/Table :db_id database-id))]
      [:in :table_id table-ids]
      [:= 1 0])))

(defn- detected-sensitive-fields
  "Active fields in `database-id` (every database when nil) whose name looks like a secret."
  [database-id]
  (->> (t2/select [:model/Field :id :name :table_id]
                  {:where [:and
                           [:= :active true]
                           (into [:or] (for [pattern secret-name-like-patterns]
                                         [:like [:lower :name] pattern]))
                           (in-database-clause database-id)]})
       (filter (comp sensitive-field-name? :name))))

(defn sensitive-fields
  "The fields in `database-id` (every database when nil) whose values MCP clients can't see: the ones an admin added,
  the ones marked sensitive in the table metadata, and the ones whose name looks like a secret (when auto-detection is
  on), minus the ones an admin excluded. Each is `{:id :name :table_id}` plus `:source`: `:manual`, `:metadata` or
  `:detected`."
  ([] (sensitive-fields nil))
  ([database-id]
   (let [manual-ids   (set (mcp-restrictions.settings/mcp-sensitive-field-ids))
         excluded-ids (set (mcp-restrictions.settings/mcp-non-sensitive-field-ids))
         manual       (when (seq manual-ids)
                        (t2/select [:model/Field :id :name :table_id]
                                   {:where [:and [:in :id manual-ids] (in-database-clause database-id)]}))
         metadata     (t2/select [:model/Field :id :name :table_id]
                                 {:where [:and
                                          [:= :active true]
                                          [:= :visibility_type "sensitive"]
                                          (in-database-clause database-id)]})
         detected     (when (mcp-restrictions.settings/mcp-sensitive-fields-auto-detect)
                        (detected-sensitive-fields database-id))]
     (->> (concat (map #(assoc % :source :manual) manual)
                  (map #(assoc % :source :metadata) metadata)
                  (map #(assoc % :source :detected) detected))
          (remove (comp excluded-ids :id))
          (m/distinct-by :id)
          (mapv #(into {} %))))))

(defn sensitive-field?
  "Whether the field with `field-id` is sensitive for the current request. Always false unless the MCP restrictions
  are enforced."
  [field-id]
  (boolean
   (and *enforced?*
        field-id
        (when-let [database-id (t2/select-one-fn :db_id :model/Table
                                                 :id (t2/select-one-fn :table_id :model/Field :id field-id))]
          (some #(= field-id (:id %)) (sensitive-fields database-id))))))

(def ^:private secret-value-patterns
  "Values that are secrets whatever column they come from."
  [;; JSON Web Tokens
   #"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"
   ;; PEM private keys
   #"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
   ;; AWS access key IDs
   #"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
   ;; OpenAI/Anthropic/Stripe-style secret keys
   #"\b(?:sk|rk)[-_](?:live[-_]|test[-_]|ant[-_]|proj[-_])?[A-Za-z0-9_-]{20,}"
   ;; GitHub and Slack tokens
   #"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})"
   ;; Google API keys
   #"\bAIza[0-9A-Za-z_-]{35}\b"
   ;; bcrypt password hashes
   #"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"])

(defn mask-secret-like-value
  "Replace anything in string `v` that looks like a secret with [[masked-value]]. Non-strings are returned unchanged."
  [v]
  (if (string? v)
    (reduce (fn [s pattern] (str/replace s pattern masked-value)) v secret-value-patterns)
    v))

(defn sensitive-field-exception
  "The exception thrown when an AI client tries to use a sensitive field in a way that could reveal its values."
  []
  (ex-info (tru "This query uses a sensitive field in a way that could reveal its values, which is not allowed for MCP clients. You can select sensitive fields, but not filter, sort, group or aggregate on them.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn sensitive-table-native-exception
  "The exception thrown when an AI client runs native SQL against a table that holds sensitive fields."
  []
  (ex-info (tru "SQL queries on tables with sensitive fields are not allowed for MCP clients. Use the query builder tools (construct_query) instead: sensitive values are masked there.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn check-native-sql-sensitive-tables!
  "Throw a 403 if any of the `sqls` run against `database-id` names a table that holds a sensitive field. Native
  results can't be traced back to fields, and SQL can read a whole row without naming its columns (`row_to_json(t)`),
  so these tables are only reachable through MBQL, where the values are masked."
  [database-id sqls]
  (when (and *enforced?* database-id (seq sqls))
    (when-let [table-ids (not-empty (into #{} (keep :table_id) (sensitive-fields database-id)))]
      (let [table-names (t2/select-fn-set :name :model/Table :id [:in table-ids])]
        (when (some (fn [sql] (some #(sql-references-table? sql %) table-names)) sqls)
          (throw (sensitive-table-native-exception)))))))
