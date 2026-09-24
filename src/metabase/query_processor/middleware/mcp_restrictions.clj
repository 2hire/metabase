(ns metabase.query-processor.middleware.mcp-restrictions
  "Query processor side of the admin-configured MCP restrictions (see [[metabase.mcp-restrictions.core]]): reject
  queries that read restricted data or use sensitive fields in a way that could reveal their values, and mask sensitive
  values in the results. Everything here is a no-op unless the request comes from an MCP client."
  (:require
   [clojure.string :as str]
   [medley.core :as m]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.query-permissions.core :as query-perms]
   [metabase.util :as u]))

(set! *warn-on-reflection* true)

(defn- native-query?
  "Whether the preprocessed legacy `query` runs a native query anywhere: at the top level, or as the source of a nested
  stage or a join (e.g. a saved SQL question used as a source)."
  [query]
  (boolean (some #(and (map? %) (contains? % :native)) (tree-seq coll? seq query))))

(defn- native-query-strings
  "Every native query in the preprocessed legacy `query`, at any depth. Non-string native queries (e.g. MongoDB
  pipelines, with their collection) are printed so they can still be searched for table names."
  [query]
  (into []
        (comp (filter map?)
              (keep :native)
              (map #(if (string? %) % (pr-str %))))
        (tree-seq coll? seq query)))

(defn- field-ref?
  [x]
  (and (vector? x) (= :field (first x))))

(def ^:private non-query-keys
  "Keys of a preprocessed query that describe it rather than being part of it, so the field refs they hold (saved result
  metadata, visualization settings) aren't uses of the field."
  #{:info :middleware :constraints :viz-settings :source-metadata :parameters})

(defn- field-refs-outside-fields
  "The ids or names of the `[:field id-or-name opts]` refs of the legacy `query` used anywhere but in a `:fields`
  clause: filters, order-bys, breakouts, aggregations, expressions and join conditions."
  [query]
  (let [refs (volatile! [])]
    (letfn [(walk [x]
              (cond
                (map? x)
                (doseq [[k v] x
                        :when (not (non-query-keys k))]
                  (if (= :fields k)
                    ;; Selected field refs are fine; anything else in `:fields` (an `[:expression ...]` ref, say) is
                    ;; walked like the rest of the query.
                    (run! walk (remove field-ref? v))
                    (walk v)))

                (field-ref? x)
                (vswap! refs conj (second x))

                (coll? x)
                (run! walk x)))]
      (walk query))
    @refs))

(defn- check-sensitive-field-usage!
  "Reject a query that uses a sensitive field outside of `:fields`: filtering, sorting, grouping or aggregating on a
  value lets a client reconstruct it even when the value itself is masked. Refs by column name (from an outer stage
  over a nested query) are matched against the sensitive field names."
  [database-id query]
  (when-let [sensitive (not-empty (mcp-restrictions/sensitive-fields database-id))]
    (let [sensitive-ids   (into #{} (map :id) sensitive)
          sensitive-names (into #{} (map (comp u/lower-case-en :name)) sensitive)
          sensitive-ref?  (fn [id-or-name]
                            (if (string? id-or-name)
                              (let [ref-name (u/lower-case-en id-or-name)]
                                (some #(or (= ref-name %) (str/ends-with? ref-name (str "__" %))) sensitive-names))
                              (contains? sensitive-ids id-or-name)))]
      (when (some sensitive-ref? (field-refs-outside-fields query))
        (throw (mcp-restrictions/sensitive-field-exception))))))

(defn check-query-allowed!
  "When the query comes from an MCP client, reject it if it reads a database or table the admin restricted, runs native
  SQL on a database that holds restricted tables or on a table that holds sensitive fields, or uses a sensitive field
  in a way that could reveal its values. Applies to every user, admins included. Takes the preprocessed legacy query."
  [{database-id :database :as outer-query}]
  (when (mcp-restrictions/enforced?)
    (let [native? (native-query? outer-query)]
      (mcp-restrictions/check-query-allowed! database-id (query-perms/query->source-table-ids outer-query) native?)
      (when native?
        (mcp-restrictions/check-native-sql-sensitive-tables! database-id (native-query-strings outer-query)))
      (check-sensitive-field-usage! database-id outer-query))))

(defn- sensitive-column-indexes
  "Indexes of the result columns that hold sensitive values: columns from a sensitive field (by field ID, or by name for
  columns without one, e.g. from a nested stage), and columns remapped from those."
  [sensitive cols]
  (let [sensitive-ids   (into #{} (map :id) sensitive)
        sensitive-names (into #{} (map (comp u/lower-case-en :name)) sensitive)
        sensitive-col?  (fn [{col-id :id col-name :name}]
                          (if col-id
                            (contains? sensitive-ids col-id)
                            (contains? sensitive-names (some-> col-name u/lower-case-en))))
        masked-names    (into #{} (comp (filter sensitive-col?) (keep :name)) cols)]
    (into #{}
          (keep-indexed (fn [i col]
                          (when (or (sensitive-col? col)
                                    (contains? masked-names ((some-fn :remapped_from :remapped-from) col)))
                            i)))
          cols)))

(defn- strip-revealing-metadata
  "Remove the column metadata that reveals a sensitive column's values: its fingerprint (min, max, averages, earliest,
  latest...) and the value/label lists of an internal remapping, which is kept empty so the remapped column is still
  produced, without labels."
  [col]
  (-> col
      (dissoc :fingerprint)
      (m/update-existing :lib/internal-remap assoc :values [] :human-readable-values [])))

(defn- mask-row
  [masked-indexes row]
  (into []
        (map-indexed (fn [i v]
                       (if (contains? masked-indexes i)
                         (mcp-restrictions/mask-value v)
                         (mcp-restrictions/mask-secret-like-value v))))
        row))

(defn mask-sensitive-values
  "Post-processing middleware: for MCP clients, mask the values of sensitive fields and strip the column metadata that
  reveals them, and mask anything that looks like a secret (a JWT, an API key, a private key...) in every other column.
  Runs right inside column annotation, so every other post-processing step (insights, result fingerprints, remapping,
  pivoting) only ever sees masked rows."
  [{database-id :database} rff]
  (if-not (mcp-restrictions/enforced?)
    rff
    (let [sensitive (mcp-restrictions/sensitive-fields database-id)]
      (fn [metadata]
        (let [masked-indexes (sensitive-column-indexes sensitive (:cols metadata))
              metadata       (update metadata :cols
                                     (fn [cols]
                                       (into []
                                             (map-indexed (fn [i col]
                                                            (cond-> col
                                                              (contains? masked-indexes i) strip-revealing-metadata)))
                                             cols)))
              rf             (rff metadata)]
          (fn
            ([] (rf))
            ([result] (rf result))
            ([result row] (rf result (mask-row masked-indexes row)))))))))
