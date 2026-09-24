(ns metabase.mcp-restrictions.core
  "Admin-configured limits on AI clients: who may use the MCP server (see [[user-allowed?]]), and which databases and
  tables are off-limits to them.

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

(declare secret-name?)

(defn do-with-restrictions-enforced
  "Impl for [[with-restrictions-enforced]]."
  [thunk]
  (binding [*enforced?* true]
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
