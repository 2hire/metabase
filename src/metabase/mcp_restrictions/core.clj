(ns metabase.mcp-restrictions.core
  "Admin-configured limits on AI clients: who may use the MCP server (see [[user-allowed?]]), which databases and
  tables are off-limits to them, and which fields hold secrets they must never see (see [[sensitive-fields]]).

  The restriction only applies while [[*enforced?*]] is bound to true, which the AI entry points do for the lifetime of
  a request: the MCP server and the Agent API it dispatches to, requests authenticated with an OAuth access token from
  the embedded authorization server (MCP clients and the Metabase CLI), and the scoped credential used by the MCP Apps
  visualization iframe. Requests authenticated with a session cookie or an API key are never affected. When enforced,
  the restriction applies to every user, admins included.

  Enforcement points:
  - the data permissions (`perms/table-permission-for-user` and friends) and the SQL visibility filters report no
    access to restricted databases and tables, so every permission check and listing hides them;
  - the query processor rejects any query that reads a restricted database or table, and any native query on a
    database that holds one (see [[check-query-allowed!]]);
  - AI clients authenticated with OAuth can only write through [[ai-client-write-allowed?]] endpoints, so they can't
    schedule work that would run later without the restrictions (alerts, subscriptions), publish data (public links),
    mint credentials that aren't restricted (API keys) or change the restrictions themselves;
  - settings that look like secrets (e.g. the embedding signing key) are obfuscated;
  - FieldValues are read-only, so a restricted request never recomputes, empties or deletes the shared cache."
  (:require
   [clojure.string :as str]
   [medley.core :as m]
   [metabase.api.common :as api]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.settings.core :as setting]
   [metabase.util :as u]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.json :as json]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:dynamic *enforced?*
  "Whether the current request comes from an AI client and must respect the MCP data restrictions. Bind it with
  [[with-restrictions-enforced]]; never read it directly outside this namespace."
  false)

(def ^:dynamic ^:private *sensitive-fields-cache*
  "Per-request cache of [[sensitive-fields]] by database ID, bound by [[with-restrictions-enforced]]."
  nil)

(declare secret-name?)

(defn do-with-restrictions-enforced
  "Impl for [[with-restrictions-enforced]]."
  [thunk]
  (binding [*enforced?*                true
            *sensitive-fields-cache* (atom {})]
    (setting/with-extra-sensitive-settings (comp secret-name? name)
      (thunk))))

(defmacro with-restrictions-enforced
  "Run `body` with the MCP data restrictions enforced."
  [& body]
  `(do-with-restrictions-enforced (fn [] ~@body)))

(defn enforced?
  "Whether the MCP data restrictions apply to the current request."
  []
  *enforced?*)

;;; ------------------------------------------------- Secret names -------------------------------------------------

(def ^:private secret-name-words
  "Words that make a name look like a secret, compared against single name segments and adjacent pairs (so `api_key`,
  `apiKey` and `APIKEY` all match `apikey`)."
  #{"password" "passwd" "pwd" "passphrase" "secret" "token" "apikey" "privatekey" "accesskey" "secretkey"
    "credential" "credentials" "salt" "otp"})

(def ^:private metadata-name-suffixes
  "Last name segments that describe a secret rather than hold it: `token_type`, `password_changed_at`, `api_key_id`."
  #{"at" "on" "type" "id" "ids" "count" "expires" "expiry" "expiration" "date" "time" "ts" "timestamp" "length" "len"
    "enabled" "required" "set" "hint" "version" "updated" "created" "changed" "status" "name" "url" "uri" "scope"
    "scopes"})

(defn- name-segments
  "Split a name into lower-case words on non-alphanumerics and camelCase boundaries."
  [s]
  (->> (str/split (str s) #"[^\p{L}\p{N}]+|(?<=\p{Ll})(?=\p{Lu})")
       (remove str/blank?)
       (map u/lower-case-en)))

(defn secret-name?
  "Whether something called `s` (a column, a setting) looks like it holds a secret. `client_secret`, `access_token`,
  `password` and `embedding-secret-key` do; `client_id`, `token_type` and `password_changed_at` don't."
  [s]
  (let [segments (vec (name-segments s))
        words    (concat segments (map str segments (rest segments)))]
    (boolean
     (and (seq segments)
          (not (metadata-name-suffixes (peek segments)))
          (some secret-name-words words)))))

;;; ---------------------------------------------- Restricted data -----------------------------------------------

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

(defn database-holds-restricted-tables?
  "Whether the database with `database-id` is restricted or holds a restricted table, for the current request."
  [database-id]
  (boolean
   (and *enforced?*
        database-id
        (or (restricted-database? database-id)
            (when-let [table-ids (not-empty (restricted-table-ids))]
              (t2/exists? :model/Table :db_id database-id :id [:in table-ids]))))))

(defn restricted-table-filter-clause
  "HoneySQL clause on `table-id-column` that keeps only unrestricted tables, or nil when nothing is restricted for the
  current request."
  [table-id-column]
  (when *enforced?*
    (let [database-ids (restricted-database-ids)
          table-ids    (restricted-table-ids)
          clauses      (cond-> []
                         (seq table-ids)
                         (conj [:not-in table-id-column table-ids])

                         (seq database-ids)
                         (conj [:not-in table-id-column ^:allow-subquery {:select [:id]
                                                                          :from   [:metabase_table]
                                                                          :where  [:in :db_id database-ids]}]))]
      (when (seq clauses)
        (into [:and] clauses)))))

(defn restricted-database-filter-clause
  "HoneySQL clause on `database-id-column` that keeps only unrestricted databases, or nil when no database is
  restricted for the current request."
  [database-id-column]
  (when *enforced?*
    (when-let [database-ids (not-empty (restricted-database-ids))]
      [:not-in database-id-column database-ids])))

(defn restriction-exception
  "The exception thrown when an AI client tries to reach restricted data."
  []
  (ex-info (tru "This data is not available to MCP clients.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn native-restriction-exception
  "The exception thrown when an AI client runs a native query on a database that holds restricted tables."
  []
  (ex-info (tru "SQL queries are not available to MCP clients on this database because it holds restricted data. Use the query builder tools (construct_query) instead.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn check-table-allowed!
  "Throw a 403 if the table is off-limits for the current request."
  [database-id table-id]
  (when (restricted-table? database-id table-id)
    (throw (restriction-exception))))

(defn check-query-allowed!
  "Throw a 403 if a query against `database-id` that reads `table-ids` touches restricted data, or if it is `native?`
  and the database holds restricted tables. Native SQL can reach a table without naming it the way a check could
  recognize (quoted or escaped identifiers, views, dynamic SQL), so on such databases MCP clients only get MBQL. No-op
  unless the restrictions are enforced for the current request."
  [database-id table-ids native?]
  (when *enforced?*
    (when (restricted-database? database-id)
      (throw (restriction-exception)))
    (when-let [restricted (not-empty (restricted-table-ids))]
      (when (some restricted table-ids)
        (throw (restriction-exception))))
    (when (and native? (database-holds-restricted-tables? database-id))
      (throw (native-restriction-exception)))))

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

;;; ------------------------------------------ AI clients on the REST API ------------------------------------------

(def ^:private ai-client-writable-routes
  "`[method uri-regex]` pairs AI clients authenticated with OAuth may call to change something. Everything they need
  to explore data and author content: run queries (which go through the query processor, so the restrictions apply),
  and create or edit questions, dashboards and collections. Deliberately left out: anything that runs later without
  the restrictions (alerts, subscriptions, transforms, model persistence), publishes data outside of authentication
  (public links, embedding), mints other credentials (API keys, users) or changes the configuration (settings,
  permissions, metadata, databases)."
  [[#{:post :delete}      #"/api/(metabase-mcp|mcp)"]
   [#{:post :put :delete} #"/api/agent/.*"]
   [#{:post}              #"/api/dataset(/.*)?"]
   [#{:post}              #"/api/embed-mcp/(drills|feedback)"]
   [#{:post}              #"/api/card"]
   [#{:put}               #"/api/card/\d+"]
   [#{:post}              #"/api/card/(pivot/)?\d+/query(/[a-z]+)?"]
   [#{:post}              #"/api/dashboard"]
   [#{:put}               #"/api/dashboard/\d+(/cards)?"]
   [#{:post}              #"/api/dashboard/(pivot/)?\d+/dashcard/\d+/card/\d+/query(/[a-z]+)?"]
   [#{:post}              #"/api/collection"]
   [#{:put}               #"/api/collection/\d+"]
   [#{:post :delete}      #"/api/bookmark/[a-z]+/\d+"]])

(defn ai-client-write-allowed?
  "Whether an AI client authenticated with OAuth may make a `method` request to `uri`. Reads are always allowed: the
  data they return goes through the restrictions."
  [method uri]
  (or (contains? #{:get :head :options} method)
      (boolean (some (fn [[methods pattern]]
                       (and (contains? methods method)
                            (re-matches pattern (str uri))))
                     ai-client-writable-routes))))

(defn forbidden-response
  "A 403 Ring response with a JSON body, already serialized so it can be returned by middleware that runs outside the
  JSON response middleware."
  [error-code message]
  {:status  403
   :headers {"Content-Type" "application/json; charset=utf-8"}
   :body    (json/encode {:error error-code :message message})})

(defn ai-client-write-denied-message
  "Message for an AI client calling an endpoint it may not write to."
  []
  (tru "MCP clients can't make this change. They can run queries and create or edit questions, dashboards and collections."))

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
                  (if (= user-id api/*current-user-id*)
                    api/*is-superuser?*
                    (t2/select-one-fn :is_superuser :model/User :id user-id))
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
  "What MCP clients see in place of a sensitive string. Other sensitive values (numbers, dates) become nil, so column
  types stay consistent for formatting and fingerprinting."
  "••••")

(defn mask-value
  "The masked form of a sensitive value `v`."
  [v]
  (cond
    (nil? v)    nil
    (string? v) masked-value
    :else       nil))

(defn sensitive-field-name?
  "Whether a field called `field-name` looks like it holds a secret. See [[secret-name?]]."
  [field-name]
  (secret-name? field-name))

(def ^:private secret-name-like-patterns
  "SQL `LIKE` patterns that pre-filter candidate field names in the app DB before [[sensitive-field-name?]] decides."
  ["%pass%" "%pwd%" "%secret%" "%token%" "%key%" "%credential%" "%salt%" "%otp%"])

(defn- in-database-clause
  "Where clause limiting fields to those of `database-id`, or nil for every database."
  [database-id]
  (when database-id
    [:in :table_id ^:allow-subquery {:select [:id] :from [:metabase_table] :where [:= :db_id database-id]}]))

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

(defn- compute-sensitive-fields
  [database-id]
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
         (mapv #(into {} %)))))

(defn sensitive-fields
  "The fields in `database-id` (every database when nil) whose values MCP clients can't see: the ones an admin added,
  the ones marked sensitive in the table metadata, and the ones whose name looks like a secret (when auto-detection is
  on), minus the ones an admin excluded. Each is `{:id :name :table_id}` plus `:source`: `:manual`, `:metadata` or
  `:detected`. Computed once per database for the lifetime of a restricted request."
  ([] (sensitive-fields nil))
  ([database-id]
   (if-let [cache *sensitive-fields-cache*]
     (or (get @cache database-id)
         (get (swap! cache assoc database-id (compute-sensitive-fields database-id)) database-id))
     (compute-sensitive-fields database-id))))

(defn sensitive-field?
  "Whether the field with `field-id` is sensitive for the current request. Always false unless the MCP restrictions
  are enforced."
  [field-id]
  (boolean
   (and *enforced?*
        field-id
        (when-let [database-id (:db_id (t2/query-one {:select [:t.db_id]
                                                      :from   [[:metabase_field :f]]
                                                      :join   [[:metabase_table :t] [:= :t.id :f.table_id]]
                                                      :where  [:= :f.id field-id]}))]
          (some #(= field-id (:id %)) (sensitive-fields database-id))))))

(defn- table-database-id
  "The database of the table with `table-id`, cached for the lifetime of a restricted request."
  [table-id]
  (let [fetch #(t2/select-one-fn :db_id :model/Table :id table-id)]
    (if-let [cache *sensitive-fields-cache*]
      (let [k [::table-database table-id]]
        (if (contains? @cache k)
          (get @cache k)
          (get (swap! cache assoc k (fetch)) k)))
      (fetch))))

(defn sensitive-field-in-table?
  "Like [[sensitive-field?]] for a field whose table is already known, with no app DB query per field once the
  table's database has been seen in the request."
  [table-id field-id]
  (boolean
   (and *enforced?*
        table-id
        field-id
        (when-let [database-id (table-database-id table-id)]
          (some #(= field-id (:id %)) (sensitive-fields database-id))))))

(def ^:private secret-value-pattern
  "Values that are secrets whatever column they come from: JSON Web Tokens, PEM private keys, AWS access key IDs,
  OpenAI/Anthropic/Stripe-style secret keys, GitHub and Slack tokens, Google API keys and bcrypt password hashes."
  (re-pattern
   (str/join "|" ["eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*"
                  "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
                  "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"
                  "\\b(?:sk|rk)[-_](?:live[-_]|test[-_]|ant[-_]|proj[-_])?[A-Za-z0-9_-]{20,}"
                  "\\b(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})"
                  "\\bAIza[0-9A-Za-z_-]{35}\\b"
                  "\\$2[abxy]?\\$\\d{2}\\$[./A-Za-z0-9]{53}"])))

(defn mask-secret-like-value
  "Replace anything in string `v` that looks like a secret with [[masked-value]]. Non-strings are returned unchanged."
  [v]
  (if (string? v)
    (str/replace v secret-value-pattern masked-value)
    v))

(defn sensitive-field-exception
  "The exception thrown when an AI client tries to use a sensitive field in a way that could reveal its values."
  []
  (ex-info (tru "This query uses a sensitive field in a way that could reveal its values, which is not allowed for MCP clients. You can select sensitive fields, but not filter, sort, group or aggregate on them.")
           {:status-code 403
            :type        :missing-required-permissions}))

(defn- table-name-pattern
  "Case-insensitive pattern matching `table-name` as a whole SQL identifier, quoted or not."
  ^java.util.regex.Pattern [table-name]
  (re-pattern (str "(?i)(?<![\\p{L}\\p{N}_$])" (java.util.regex.Pattern/quote table-name) "(?![\\p{L}\\p{N}_$])")))

(defn check-native-sql-sensitive-tables!
  "Throw a 403 if any of the `sqls` native query strings run against `database-id` names a table that holds a sensitive
  field. Native results can't be traced back to fields, and SQL can read a whole row without naming its columns
  (`row_to_json(t)`, `t::text`), so these tables are only reachable through MBQL, where the values are masked.

  Any mention of such a table's name as a standalone identifier counts, including inside a string literal, so false
  positives block a query rather than leak data. SQL that reaches such a table without naming it (identifier escapes
  like `U&\"...\"`, a view over it, SQL assembled at run time from pieces) isn't recognized: restrict the table or its
  database when that matters."
  [database-id sqls]
  (when (and *enforced?* database-id (seq sqls))
    (when-let [table-ids (not-empty (into #{} (keep :table_id) (sensitive-fields database-id)))]
      (let [patterns (map table-name-pattern (t2/select-fn-set :name :model/Table :id [:in table-ids]))]
        (when (some (fn [sql] (some #(re-find % sql) patterns)) sqls)
          (throw (ex-info (tru "SQL queries on tables with sensitive fields are not available to MCP clients. Use the query builder tools (construct_query) instead: sensitive values are masked there.")
                          {:status-code 403
                           :type        :missing-required-permissions})))))))
