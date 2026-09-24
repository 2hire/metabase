import { type ReactNode, useMemo, useState } from "react";
import type { WithRouterProps } from "react-router";
import { t } from "ttag";

import NoResults from "assets/img/no_results.svg";
import { SettingsPageWrapper } from "metabase/admin/components/SettingsSection";
import { useListMcpAuditLogQuery, useListUsersQuery } from "metabase/api";
import { EmptyState } from "metabase/common/components/EmptyState";
import { DelayedLoadingAndErrorWrapper } from "metabase/common/components/LoadingAndErrorWrapper/DelayedLoadingAndErrorWrapper";
import { PaginationControls } from "metabase/common/components/PaginationControls";
import {
  type QueryParam,
  type UrlStateConfig,
  getFirstParamValue,
  useUrlState,
} from "metabase/common/hooks/use-url-state";
import {
  Badge,
  Box,
  Card,
  Code,
  Ellipsified,
  Group,
  Modal,
  Select,
  Stack,
  Text,
  TreeTable,
  type TreeTableColumnDef,
  useTreeTableInstance,
} from "metabase/ui";
import type { MetabaseColorKey } from "metabase/ui/colors/types";
import MetabaseSettings from "metabase/utils/settings";
import { formatDateTimeWithUnit } from "metabase/visualizations/lib/formatting";
import type {
  McpAuditLogEntry,
  McpAuditLogStatus,
  User,
} from "metabase-types/api";

export const MCP_AUDIT_LOG_PAGE_SIZE = 50;

// Users and methods come from the server, so their option values get a prefix that the sentinel can't collide with.
const ALL = "all";
const USER_OPTION_PREFIX = "user:";
const METHOD_OPTION_PREFIX = "method:";

const STATUSES: McpAuditLogStatus[] = ["success", "error", "denied"];

const STATUS_COLORS: Record<McpAuditLogStatus, MetabaseColorKey> = {
  success: "success",
  error: "error",
  denied: "warning",
};

const getStatusLabel = (status: McpAuditLogStatus) => {
  switch (status) {
    case "success":
      return t`Success`;
    case "error":
      return t`Error`;
    case "denied":
      return t`Denied`;
  }
};

const getAuthMethodLabel = (authMethod: string) => {
  switch (authMethod) {
    case "session":
      return t`Session`;
    case "api-key":
      return t`API key`;
    case "oauth":
      return t`OAuth token`;
    case "mcp-ui":
      return t`MCP Apps iframe`;
    case "jwt":
      return t`Agent API JWT`;
    default:
      return authMethod;
  }
};

const getMethodLabel = (method: string) =>
  method === "other" ? t`Other` : method;

const formatTimestamp = (value: string) =>
  formatDateTimeWithUnit(value, "minute", {
    ...MetabaseSettings.formattingOptions(),
    time_enabled: "seconds",
  });

const isStatus = (value: string): value is McpAuditLogStatus =>
  STATUSES.some((status) => status === value);

type UrlState = {
  page: number;
  userId: number | null;
  method: string | null;
  status: McpAuditLogStatus | null;
};

const urlStateConfig: UrlStateConfig<UrlState> = {
  parse: (query) => ({
    page: parseNonNegativeInt(query.page) ?? 0,
    userId: parseNonNegativeInt(query.user_id) || null,
    method: getFirstParamValue(query.method) || null,
    status: parseStatus(query.status),
  }),
  serialize: ({ page, userId, method, status }) => ({
    page: page === 0 ? undefined : String(page),
    user_id: userId == null ? undefined : String(userId),
    method: method ?? undefined,
    status: status ?? undefined,
  }),
};

function parseNonNegativeInt(param: QueryParam): number | null {
  const parsed = parseInt(getFirstParamValue(param) || "", 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function parseStatus(param: QueryParam): McpAuditLogStatus | null {
  const value = getFirstParamValue(param);
  return value && isStatus(value) ? value : null;
}

const getUserLabel = (user: User) => {
  const label = user.common_name
    ? `${user.common_name} (${user.email})`
    : user.email;
  return user.is_active ? label : t`${label} (deactivated)`;
};

const withoutPrefix = (value: string | null, prefix: string) =>
  value?.startsWith(prefix) ? value.slice(prefix.length) : null;

const getEntryUserLabel = (entry: McpAuditLogEntry) => {
  const name = [entry.user_first_name, entry.user_last_name]
    .filter(Boolean)
    .join(" ");
  return entry.user_email ?? (name || "—");
};

export const McpAuditLogPage = ({ location }: WithRouterProps) => {
  const [{ page, userId, method, status }, { patchUrlState }] = useUrlState(
    location,
    urlStateConfig,
  );
  const [selectedEntry, setSelectedEntry] = useState<McpAuditLogEntry | null>(
    null,
  );

  const { data, isLoading, error } = useListMcpAuditLogQuery(
    {
      limit: MCP_AUDIT_LOG_PAGE_SIZE,
      offset: page * MCP_AUDIT_LOG_PAGE_SIZE,
      "user-id": userId ?? undefined,
      method: method ?? undefined,
      status: status ?? undefined,
    },
    { refetchOnMountOrArgChange: true },
  );
  // Deactivated users keep their audit log entries, so they can be filtered on too.
  const { data: usersResponse } = useListUsersQuery({ status: "all" });

  const entries = data?.data ?? [];
  const total = data?.total ?? 0;
  const methods = useMemo(() => [...new Set(data?.methods ?? [])], [data]);

  const userOptions = useMemo(
    () =>
      (usersResponse?.data ?? []).map((user) => ({
        value: `${USER_OPTION_PREFIX}${user.id}`,
        label: getUserLabel(user),
      })),
    [usersResponse],
  );

  return (
    <SettingsPageWrapper
      title={t`MCP audit log`}
      description={t`Every request MCP clients made: the tools they called, the resources they read, the API calls they made directly, and the requests that were refused.`}
      h="100%"
      mih={0}
      w="100%"
      maw="72rem"
      mx="auto"
      p="xl"
    >
      <Group gap="sm">
        <Select
          data={[{ value: ALL, label: t`All users` }, ...userOptions]}
          value={userId == null ? ALL : `${USER_OPTION_PREFIX}${userId}`}
          onChange={(value) => {
            const id = withoutPrefix(value, USER_OPTION_PREFIX);
            patchUrlState({ userId: id ? Number(id) : null, page: 0 });
          }}
          searchable
          aria-label={t`Filter by user`}
        />
        <Select
          data={[
            { value: ALL, label: t`All methods` },
            ...methods.map((value) => ({
              value: `${METHOD_OPTION_PREFIX}${value}`,
              label: getMethodLabel(value),
            })),
          ]}
          value={method == null ? ALL : `${METHOD_OPTION_PREFIX}${method}`}
          onChange={(value) =>
            patchUrlState({
              method: withoutPrefix(value, METHOD_OPTION_PREFIX),
              page: 0,
            })
          }
          aria-label={t`Filter by method`}
        />
        <Select
          data={[
            { value: ALL, label: t`All outcomes` },
            ...STATUSES.map((value) => ({
              value,
              label: getStatusLabel(value),
            })),
          ]}
          value={status ?? ALL}
          onChange={(value) =>
            patchUrlState({
              status: value && isStatus(value) ? value : null,
              page: 0,
            })
          }
          aria-label={t`Filter by outcome`}
        />
      </Group>

      <AuditLogTable
        entries={entries}
        isLoading={isLoading}
        error={error}
        onSelect={setSelectedEntry}
      />
      <Group justify="end">
        <PaginationControls
          page={page}
          pageSize={MCP_AUDIT_LOG_PAGE_SIZE}
          itemsLength={entries.length}
          total={total}
          onPreviousPage={() => patchUrlState({ page: page - 1 })}
          onNextPage={() => patchUrlState({ page: page + 1 })}
        />
      </Group>

      <EntryDetailsModal
        entry={selectedEntry}
        onClose={() => setSelectedEntry(null)}
      />
    </SettingsPageWrapper>
  );
};

function getColumns(): TreeTableColumnDef<McpAuditLogEntry>[] {
  return [
    {
      id: "created-at",
      header: t`Date`,
      width: 190,
      accessorFn: (entry) => entry.created_at,
      cell: ({ row }) => (
        <Text>{formatTimestamp(row.original.created_at)}</Text>
      ),
    },
    {
      id: "user",
      header: t`User`,
      minWidth: 120,
      maxWidth: 220,
      accessorFn: getEntryUserLabel,
      cell: ({ getValue }) => <Ellipsified>{String(getValue())}</Ellipsified>,
    },
    {
      id: "method",
      header: t`Method`,
      width: 140,
      accessorFn: (entry) => entry.method,
      cell: ({ getValue }) => (
        <Ellipsified fw="bold">{String(getValue())}</Ellipsified>
      ),
    },
    {
      id: "target",
      header: t`Target`,
      minWidth: 120,
      accessorFn: (entry) => entry.target ?? "—",
      cell: ({ getValue }) => <Ellipsified>{String(getValue())}</Ellipsified>,
    },
    {
      id: "status",
      header: t`Outcome`,
      width: 110,
      cell: ({ row }) => (
        <Badge color={STATUS_COLORS[row.original.status]} variant="light">
          {getStatusLabel(row.original.status)}
        </Badge>
      ),
    },
    {
      id: "duration",
      header: t`Duration`,
      width: 100,
      accessorFn: (entry) =>
        entry.duration_ms == null ? "—" : t`${entry.duration_ms} ms`,
      cell: ({ getValue }) => <Text>{String(getValue())}</Text>,
    },
  ];
}

function AuditLogTable({
  entries,
  isLoading,
  error,
  onSelect,
}: {
  entries: McpAuditLogEntry[];
  isLoading: boolean;
  error: unknown;
  onSelect: (entry: McpAuditLogEntry) => void;
}) {
  const columns = useMemo(() => getColumns(), []);
  const instance = useTreeTableInstance<McpAuditLogEntry>({
    data: entries,
    columns,
    getNodeId: (entry) => String(entry.id),
    enableSorting: false,
    // Enter on the row focused with the arrow keys opens its details, like a click.
    onRowActivate: (row) => onSelect(row.original),
  });

  if (isLoading || error) {
    return <DelayedLoadingAndErrorWrapper loading={isLoading} error={error} />;
  }

  return (
    <Card
      withBorder
      p={0}
      flex="1"
      mih={0}
      display="flex"
      style={{ flexDirection: "column", overflow: "hidden" }}
      data-testid="mcp-audit-log-table"
    >
      <TreeTable
        instance={instance}
        hierarchical={false}
        ariaLabel={t`MCP audit log`}
        onRowClick={(row) => onSelect(row.original)}
        emptyState={
          <Box p="xl" ta="center" data-testid="mcp-audit-log-empty">
            <EmptyState
              title={t`No requests`}
              illustrationElement={<img src={NoResults} />}
              spacing="sm"
            />
          </Box>
        }
      />
    </Card>
  );
}

const formatArguments = (value: string) => {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    // Long arguments are truncated, so they are not always valid JSON.
    return value;
  }
};

function EntryDetailsModal({
  entry,
  onClose,
}: {
  entry: McpAuditLogEntry | null;
  onClose: () => void;
}) {
  return (
    <Modal
      opened={entry != null}
      onClose={onClose}
      size="xl"
      title={entry ? `${entry.method} ${entry.target ?? ""}` : ""}
    >
      {entry && (
        <Stack gap="md" data-testid="mcp-audit-log-details">
          <DetailRow label={t`Date`}>
            {formatTimestamp(entry.created_at)}
          </DetailRow>
          <DetailRow label={t`User`}>{getEntryUserLabel(entry)}</DetailRow>
          <DetailRow label={t`Outcome`}>
            <Badge color={STATUS_COLORS[entry.status]} variant="light">
              {getStatusLabel(entry.status)}
            </Badge>
          </DetailRow>
          <DetailRow label={t`Authentication`}>
            {getAuthMethodLabel(entry.auth_method)}
          </DetailRow>
          <DetailRow label={t`MCP session`}>
            {entry.mcp_session_id ?? "—"}
          </DetailRow>
          <DetailRow label={t`IP address`}>{entry.ip_address ?? "—"}</DetailRow>
          <DetailRow label={t`User agent`}>{entry.user_agent ?? "—"}</DetailRow>
          {entry.error_message && (
            <DetailRow label={t`Error`}>
              <Code block>{entry.error_message}</Code>
            </DetailRow>
          )}
          {entry.arguments && (
            <DetailRow label={t`Arguments`}>
              <Code block>{formatArguments(entry.arguments)}</Code>
            </DetailRow>
          )}
        </Stack>
      )}
    </Modal>
  );
}

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <Stack gap={4}>
      <Text size="sm" c="text-secondary" fw="bold">
        {label}
      </Text>
      <Box>{children}</Box>
    </Stack>
  );
}
