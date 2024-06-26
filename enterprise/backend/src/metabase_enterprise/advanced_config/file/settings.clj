(ns metabase-enterprise.advanced-config.file.settings
  (:require
   [clojure.spec.alpha :as s]
   [metabase-enterprise.advanced-config.file.interface :as advanced-config.file.i]
   [metabase.models.setting :as setting]
   [metabase.util.log :as log]))

(defmethod advanced-config.file.i/section-spec :settings
  [_section-name]
  (s/map-of keyword? any?))

(defmethod advanced-config.file.i/initialize-section! :settings
  [_section-name settings]
  (log/info "Setting setting values from config file")
  (doseq [[setting-name setting-value] settings]
    (log/infof "Setting value for Setting %s" setting-name)
    (setting/set! setting-name setting-value)))
