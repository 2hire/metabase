import { useMemo, useState } from "react";
import { t } from "ttag";
import _ from "underscore";

import { SettingsSection } from "metabase/admin/components/SettingsSection";
import { SettingHeader } from "metabase/admin/settings/components/SettingHeader";
import {
  skipToken,
  useGetMcpSensitiveFieldsQuery,
  useGetTableQueryMetadataQuery,
  useListDatabasesQuery,
  useListTablesQuery,
} from "metabase/api";
import { useAdminSetting } from "metabase/api/utils";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Flex,
  Group,
  Icon,
  Select,
  Stack,
  Switch,
  Text,
} from "metabase/ui";
import type {
  Database,
  FieldId,
  McpFieldLocation,
  McpSensitiveFieldSource,
  Table,
} from "metabase-types/api";

const getSourceLabel = (source: McpSensitiveFieldSource) => {
  switch (source) {
    case "detected":
      return t`Detected by name`;
    case "manual":
      return t`Added by an admin`;
    case "metadata":
      return t`Sensitive in table metadata`;
  }
};

const getFieldLocation = (field: McpFieldLocation) => {
  const table = [field.schema, field.table_name].filter(Boolean).join(".");
  return `${field.database_name ?? ""} › ${table}.${field.name}`;
};

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

export const McpSensitiveFieldsSettings = () => {
  const { data } = useGetMcpSensitiveFieldsQuery();
  const {
    value: autoDetect,
    updateSetting,
    updateSettings,
  } = useAdminSetting("mcp-sensitive-fields-auto-detect");
  const { value: manualIds } = useAdminSetting("mcp-sensitive-field-ids");
  const { value: excludedIds } = useAdminSetting("mcp-non-sensitive-field-ids");

  const sensitive = data?.sensitive ?? [];
  const excluded = data?.excluded ?? [];

  const markSensitive = (fieldId: FieldId) =>
    updateSettings({
      "mcp-sensitive-field-ids": _.uniq([...(manualIds ?? []), fieldId]),
      "mcp-non-sensitive-field-ids": (excludedIds ?? []).filter(
        (id) => id !== fieldId,
      ),
    });

  const markNotSensitive = (fieldId: FieldId) =>
    updateSettings({
      "mcp-sensitive-field-ids": (manualIds ?? []).filter(
        (id) => id !== fieldId,
      ),
      "mcp-non-sensitive-field-ids": _.uniq([...(excludedIds ?? []), fieldId]),
    });

  const restoreDefault = (fieldId: FieldId) =>
    updateSetting({
      key: "mcp-non-sensitive-field-ids",
      value: (excludedIds ?? []).filter((id) => id !== fieldId),
    });

  return (
    <SettingsSection
      title={t`Sensitive fields`}
      description={t`MCP clients see •••• instead of the values of these fields, and can't filter, sort, group or aggregate on them. SQL queries on their tables are rejected. Values that look like secrets (JWTs, API keys, private keys, password hashes) are masked in every column.`}
    >
      <Stack gap="lg">
        <Switch
          label={t`Detect sensitive fields by name (password, secret, token, API key…)`}
          checked={autoDetect !== false}
          onChange={(event) =>
            updateSetting({
              key: "mcp-sensitive-fields-auto-detect",
              value: event.target.checked,
            })
          }
          size="sm"
          w="auto"
        />

        <Box>
          <SettingHeader
            id="mcp-sensitive-fields"
            title={t`Fields treated as sensitive`}
          />
          {sensitive.length === 0 ? (
            <Text c="text-secondary" mt="sm">{t`No sensitive fields.`}</Text>
          ) : (
            <Stack gap="xs" mt="sm" data-testid="mcp-sensitive-fields">
              {sensitive.map((field) => (
                <Flex key={field.id} align="center" gap="sm">
                  <Text flex={1}>{getFieldLocation(field)}</Text>
                  <Badge variant="light">{getSourceLabel(field.source)}</Badge>
                  <ActionIcon
                    aria-label={t`Stop treating ${field.name} as sensitive`}
                    onClick={() => markNotSensitive(field.id)}
                  >
                    <Icon name="close" />
                  </ActionIcon>
                </Flex>
              ))}
            </Stack>
          )}
        </Box>

        <AddSensitiveField onAdd={markSensitive} />

        {excluded.length > 0 && (
          <Box>
            <SettingHeader
              id="mcp-non-sensitive-fields"
              title={t`Never treated as sensitive`}
            />
            <Stack gap="xs" mt="sm" data-testid="mcp-non-sensitive-fields">
              {excluded.map((field) => (
                <Flex key={field.id} align="center" gap="sm">
                  <Text flex={1}>{getFieldLocation(field)}</Text>
                  <Button
                    variant="subtle"
                    size="xs"
                    aria-label={t`Restore ${field.name}`}
                    onClick={() => restoreDefault(field.id)}
                  >
                    {t`Restore`}
                  </Button>
                </Flex>
              ))}
            </Stack>
          </Box>
        )}
      </Stack>
    </SettingsSection>
  );
};

function AddSensitiveField({ onAdd }: { onAdd: (fieldId: FieldId) => void }) {
  const [tableId, setTableId] = useState<string | null>(null);
  const [fieldId, setFieldId] = useState<string | null>(null);

  const { data: databasesResponse } = useListDatabasesQuery();
  const { data: tables = [] } = useListTablesQuery();
  const { data: table } = useGetTableQueryMetadataQuery(
    tableId ? { id: Number(tableId) } : skipToken,
  );

  const tableOptions = useMemo(
    () => getTableOptions(tables, databasesResponse?.data ?? []),
    [tables, databasesResponse],
  );
  const fieldOptions = useMemo(
    () =>
      _.sortBy(
        (table?.fields ?? []).map((field) => ({
          value: String(field.id),
          label: field.name,
        })),
        "label",
      ),
    [table],
  );

  const handleAdd = () => {
    if (fieldId) {
      onAdd(Number(fieldId));
      setFieldId(null);
    }
  };

  return (
    <Box>
      <SettingHeader
        id="mcp-add-sensitive-field"
        title={t`Add a sensitive field`}
      />
      <Group align="flex-end" gap="sm" mt="sm">
        <Select
          label={t`Table`}
          placeholder={t`Select a table`}
          data={tableOptions}
          value={tableId}
          onChange={(value) => {
            setTableId(value);
            setFieldId(null);
          }}
          searchable
        />
        <Select
          label={t`Field`}
          placeholder={t`Select a field`}
          data={fieldOptions}
          value={fieldId}
          onChange={setFieldId}
          disabled={!tableId}
          searchable
        />
        <Button onClick={handleAdd} disabled={!fieldId}>{t`Add`}</Button>
      </Group>
    </Box>
  );
}
