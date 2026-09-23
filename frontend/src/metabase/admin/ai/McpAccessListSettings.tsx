import { useMemo } from "react";
import { t } from "ttag";

import { SettingsSection } from "metabase/admin/components/SettingsSection";
import { useListPermissionsGroupsQuery, useListUsersQuery } from "metabase/api";
import { useAdminSetting } from "metabase/api/utils";
import { MultiSelect, Stack } from "metabase/ui";
import type { GroupListQuery, UserListResult } from "metabase-types/api";

const toIds = (values: string[]) => values.map((value) => Number(value));

const toValues = (ids: number[] | null | undefined) =>
  (ids ?? []).map((id) => String(id));

const getUserOptions = (users: UserListResult[]) =>
  users.map((user) => ({
    value: String(user.id),
    label: user.common_name
      ? `${user.common_name} (${user.email})`
      : user.email,
  }));

const getGroupOptions = (groups: GroupListQuery[]) =>
  groups.map((group) => ({ value: String(group.id), label: group.name }));

export const McpAccessListSettings = () => {
  const { data: usersResponse, isLoading: isLoadingUsers } =
    useListUsersQuery();
  const { data: groups = [], isLoading: isLoadingGroups } =
    useListPermissionsGroupsQuery({});

  const { value: allowedUserIds, updateSetting } = useAdminSetting(
    "mcp-allowed-user-ids",
  );
  const { value: allowedGroupIds } = useAdminSetting("mcp-allowed-group-ids");

  const userOptions = useMemo(
    () => getUserOptions(usersResponse?.data ?? []),
    [usersResponse],
  );
  const groupOptions = useMemo(() => getGroupOptions(groups), [groups]);

  return (
    <SettingsSection
      title={t`Access`}
      description={t`Choose who can use the MCP server and the Agent API. While both lists are empty, everyone can. Admins always can.`}
    >
      <Stack gap="lg">
        <MultiSelect
          label={t`Allowed users`}
          placeholder={t`Select users`}
          data={userOptions}
          value={toValues(allowedUserIds)}
          disabled={isLoadingUsers}
          onChange={(values) =>
            updateSetting({ key: "mcp-allowed-user-ids", value: toIds(values) })
          }
          searchable
          clearable
        />
        <MultiSelect
          label={t`Allowed groups`}
          description={t`Every member of these groups can use the MCP server.`}
          placeholder={t`Select groups`}
          data={groupOptions}
          value={toValues(allowedGroupIds)}
          disabled={isLoadingGroups}
          onChange={(values) =>
            updateSetting({
              key: "mcp-allowed-group-ids",
              value: toIds(values),
            })
          }
          searchable
          clearable
        />
      </Stack>
    </SettingsSection>
  );
};
