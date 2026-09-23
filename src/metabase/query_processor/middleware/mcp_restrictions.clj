(ns metabase.query-processor.middleware.mcp-restrictions
  "Query processor side of the admin-configured MCP restrictions (see [[metabase.mcp-restrictions.core]]): reject
  queries that read restricted data or use sensitive fields in a way that could reveal their values, and mask sensitive
  values in the results. Everything here is a no-op unless the request comes from an MCP client."
  (:require
   [clojure.string :as str]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.query-permissions.core :as query-perms]
   [metabase.util :as u]))

(set! *warn-on-reflection* true)

(defn- native-query-strings
  "Every native query in the preprocessed legacy `query`, at any depth: the top-level `:native` map as well as native
  source queries of nested stages and joins. Non-string native queries (e.g. MongoDB pipelines) are printed so they can
  still be searched for table names."
  [query]
  (into []
        (comp (filter map?)
              (keep :native)
              (keep #(if (map? %) (:query %) %))
              (map #(if (string? %) % (pr-str %))))
        (tree-seq coll? seq query)))

(defn- field-ref?
  [x]
  (and (vector? x) (= :field (first x))))

(defn- field-refs-by-position
  "Split the `[:field id-or-name opts]` refs of the legacy `query` into those that only select a column (inside a
  `:fields` clause) and those used anywhere else: filters, order-bys, breakouts, aggregations, expressions and join
  conditions."
  [query]
  (let [selected (volatile! [])
        other    (volatile! [])]
    (letfn [(collect-refs [acc x]
              (doseq [node (tree-seq coll? seq x)
                      :when (field-ref? node)]
                (vswap! acc conj (second node))))
            (walk [x]
              (cond
                (map? x)
                (doseq [[k v] x]
                  (if (= :fields k)
                    (do (collect-refs selected (filter field-ref? v))
                        ;; `:fields` can also hold `[:expression ...]` refs etc.; anything nested in a field ref (a
                        ;; source field for an implicit join, say) is still only a column being selected.
                        (collect-refs other (remove field-ref? v)))
                    (walk v)))

                (field-ref? x)
                (vswap! other conj (second x))

                (coll? x)
                (run! walk x)))]
      (walk query))
    {:selected @selected
     :other    @other}))

(defn- check-sensitive-field-usage!
  "Reject a query that uses a sensitive field outside of `:fields`: filtering, sorting, grouping or aggregating on a
  value lets a client reconstruct it even when the value itself is masked. Refs by column name (from an outer stage
  over a nested query) are matched against the sensitive field names."
  [database-id query sqls]
  (let [sensitive (mcp-restrictions/sensitive-fields database-id)]
    (when (seq sensitive)
      (let [sensitive-ids   (into #{} (map :id) sensitive)
            sensitive-names (into #{} (map (comp u/lower-case-en :name)) sensitive)
            {:keys [other]} (field-refs-by-position query)
            sensitive-ref?  (fn [id-or-name]
                              (if (string? id-or-name)
                                (let [ref-name (u/lower-case-en id-or-name)]
                                  (some #(or (= ref-name %) (str/ends-with? ref-name (str "__" %))) sensitive-names))
                                (contains? sensitive-ids id-or-name)))]
        (when (some sensitive-ref? other)
          (throw (mcp-restrictions/sensitive-field-exception)))
        (mcp-restrictions/check-native-sql-sensitive-tables! database-id sqls)))))

(defn check-query-allowed!
  "When the query comes from an MCP client, reject it if it reads a database or table the admin restricted, or uses a
  sensitive field in a way that could reveal its values. Applies to every user, admins included. Takes the
  preprocessed legacy query."
  [{database-id :database :as outer-query}]
  (when (mcp-restrictions/enforced?)
    (let [sqls (native-query-strings outer-query)]
      (mcp-restrictions/check-query-allowed! database-id (query-perms/query->source-table-ids outer-query) sqls)
      (check-sensitive-field-usage! database-id outer-query sqls))))

(defn- sensitive-column-indexes
  "Indexes of the result columns that come from a sensitive field, matched by field ID or, for columns without one
  (native queries, nested stages), by name."
  [sensitive cols]
  (let [sensitive-ids   (into #{} (map :id) sensitive)
        sensitive-names (into #{} (map (comp u/lower-case-en :name)) sensitive)]
    (into #{}
          (keep-indexed (fn [i {col-id :id col-name :name}]
                          (when (or (contains? sensitive-ids col-id)
                                    (some-> col-name u/lower-case-en sensitive-names))
                            i)))
          cols)))

(defn- mask-row
  [masked-indexes row]
  (into []
        (map-indexed (fn [i v]
                       (cond
                         (contains? masked-indexes i) (when (some? v) mcp-restrictions/masked-value)
                         (string? v)                  (mcp-restrictions/mask-secret-like-value v)
                         :else                        v)))
        row))

(defn mask-sensitive-values
  "Post-processing middleware: for MCP clients, replace the values of sensitive fields with a mask, and mask anything
  that looks like a secret (a JWT, an API key, a private key...) in every other column."
  [{database-id :database} rff]
  (if-not (mcp-restrictions/enforced?)
    rff
    (let [sensitive (mcp-restrictions/sensitive-fields database-id)]
      (fn [metadata]
        (let [masked-indexes (sensitive-column-indexes sensitive (:cols metadata))
              rf             (rff metadata)]
          (fn
            ([] (rf))
            ([result] (rf result))
            ([result row] (rf result (mask-row masked-indexes row)))))))))
