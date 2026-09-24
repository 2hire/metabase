import { t } from "ttag";

import { SettingsSection } from "metabase/admin/components/SettingsSection";
import { AdminSettingInput } from "metabase/admin/settings/components/widgets/AdminSettingInput";
import { Link } from "metabase/common/components/Link";
import { useSetting } from "metabase/common/hooks";
import { Stack } from "metabase/ui";

export const MCP_AUDIT_LOG_PATH = "/admin/metabot/mcp/audit-log";

export const McpAuditLogSettings = () => {
  const isEnabled = useSetting("mcp-audit-log-enabled?") !== false;

  return (
    <SettingsSection
      title={t`Audit log`}
      description={t`Record every request MCP clients make: the tools they call with their arguments, the resources they read, and the requests the access list refuses. Secret-looking arguments are masked.`}
    >
      <Stack gap="lg">
        <AdminSettingInput
          name="mcp-audit-log-enabled?"
          title={t`Record MCP requests`}
          inputType="boolean"
        />
        <AdminSettingInput
          name="mcp-audit-log-retention-days"
          title={t`Days to keep entries`}
          description={t`Older entries are deleted every night. Set it to 0 to keep them forever.`}
          inputType="number"
          disabled={!isEnabled}
        />
        <Link variant="brand" to={MCP_AUDIT_LOG_PATH}>
          {t`View the audit log`}
        </Link>
      </Stack>
    </SettingsSection>
  );
};
