import { useMemo, useState } from "react";
import { t } from "ttag";
import _ from "underscore";

import { SettingsSection } from "metabase/admin/components/SettingsSection";
import { useListDatabasesQuery, useListTablesQuery } from "metabase/api";
import { useAdminSetting } from "metabase/api/utils";
import { MultiSelect, Stack } from "metabase/ui";
import type { Database, Table } from "metabase-types/api";

const toIds = (values: string[]) => values.map((value) => Number(value));

const toValues = (ids: number[] | null | undefined) =>
  (ids ?? []).map((id) => String(id));

const getDatabaseOptions = (databases: Database[]) =>
  databases.map((database) => ({
    value: String(database.id),
    label: database.name,
  }));

const getTableLabel = (table: Table) =>
  table.schema ? `${table.schema}.${table.name}` : table.name;

const getTableOptions = (tables: Table[], databases: Database[]) => {
  const databaseNames = new Map(databases.map((db) => [db.id, db.name]));
  const tablesByDatabase = _.groupBy(
    tables,
    (table) => databaseNames.get(table.db_id) ?? String(table.db_id),
  );

  return Object.entries(tablesByDatabase).map(([group, groupTables]) => ({
    group,
    items: _.sortBy(
      groupTables.map((table) => ({
        value: String(table.id),
        label: getTableLabel(table),
      })),
      "label",
    ),
  }));
};

export const McpRestrictedDataSettings = () => {
  const { data: databasesResponse, isLoading: isLoadingDatabases } =
    useListDatabasesQuery();
  const { data: tables = [], isLoading: isLoadingTables } =
    useListTablesQuery();

  const { value: restrictedDatabaseIds, updateSetting } = useAdminSetting(
    "mcp-restricted-database-ids",
  );
  const { value: restrictedTableIds } = useAdminSetting(
    "mcp-restricted-table-ids",
  );

  // Each change saves the whole list, so the latest selection lives in local state: deriving it from the saved setting
  // would drop a pick made before the previous save had been refetched.
  const [databaseValues, setDatabaseValues] = useState<string[] | null>(null);
  const [tableValues, setTableValues] = useState<string[] | null>(null);

  const databases = useMemo(
    () => databasesResponse?.data ?? [],
    [databasesResponse],
  );
  const databaseOptions = useMemo(
    () => getDatabaseOptions(databases),
    [databases],
  );
  const tableOptions = useMemo(
    () => getTableOptions(tables, databases),
    [tables, databases],
  );

  return (
    <SettingsSection
      title={t`Restricted data`}
      description={t`Databases and tables selected here can't be seen or queried by MCP clients and the Agent API, not even by admins. The rest of Metabase is not affected.`}
    >
      <Stack gap="lg">
        <MultiSelect
          label={t`Restricted databases`}
          description={t`Every table in these databases is restricted.`}
          placeholder={t`Select databases`}
          data={databaseOptions}
          value={databaseValues ?? toValues(restrictedDatabaseIds)}
          disabled={isLoadingDatabases}
          onChange={(values) => {
            setDatabaseValues(values);
            updateSetting({
              key: "mcp-restricted-database-ids",
              value: toIds(values),
            });
          }}
          searchable
          clearable
        />
        <MultiSelect
          label={t`Restricted tables`}
          description={t`MCP clients also can't run SQL queries on a database that holds one of these tables.`}
          placeholder={t`Select tables`}
          data={tableOptions}
          value={tableValues ?? toValues(restrictedTableIds)}
          disabled={isLoadingTables}
          onChange={(values) => {
            setTableValues(values);
            updateSetting({
              key: "mcp-restricted-table-ids",
              value: toIds(values),
            });
          }}
          searchable
          clearable
        />
      </Stack>
    </SettingsSection>
  );
};
