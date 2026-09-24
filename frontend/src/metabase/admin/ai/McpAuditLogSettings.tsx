import { useEffect, useState } from "react";
import { t } from "ttag";

import { SettingsSection } from "metabase/admin/components/SettingsSection";
import { SettingHeader } from "metabase/admin/settings/components/SettingHeader";
import { AdminSettingInput } from "metabase/admin/settings/components/widgets/AdminSettingInput";
import { useAdminSetting } from "metabase/api/utils";
import { Link } from "metabase/common/components/Link";
import { SetByEnvVar } from "metabase/common/components/SetByEnvVar";
import { Box, Stack, TextInput } from "metabase/ui";

export const MCP_AUDIT_LOG_PATH = "/admin/metabot/mcp/audit-log";

const RETENTION_SETTING = "mcp-audit-log-retention-days";

export const McpAuditLogSettings = () => (
  <SettingsSection
    title={t`Audit log`}
    description={t`Record every request MCP clients make: the tools they call with their arguments, the resources they read, the API calls they make directly, and the requests that are refused. Secret-looking values are masked.`}
  >
    <Stack gap="lg">
      <AdminSettingInput
        name="mcp-audit-log-enabled?"
        title={t`Record MCP requests`}
        inputType="boolean"
      />
      <RetentionDaysInput />
      <Link variant="brand" to={MCP_AUDIT_LOG_PATH}>
        {t`View the audit log`}
      </Link>
    </Stack>
  </SettingsSection>
);

/** The number of days to keep, or null when `value` isn't a non-negative integer. */
const parseRetentionDays = (value: string): number | null =>
  /^\d+$/.test(value.trim()) ? Number(value.trim()) : null;

/**
 * Only ever saves a whole number of days: anything else would make the backend fall back to the default retention,
 * and the nightly purge would delete entries the admin meant to keep. It stays editable while recording is off,
 * because the purge keeps applying it.
 */
function RetentionDaysInput() {
  const { value, updateSetting, isLoading, settingDetails } =
    useAdminSetting(RETENTION_SETTING);
  const savedValue = value == null ? "" : String(value);
  const [localValue, setLocalValue] = useState(savedValue);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLocalValue(savedValue);
    setError(null);
  }, [savedValue]);

  if (isLoading) {
    return null;
  }

  const handleBlur = () => {
    const days = parseRetentionDays(localValue);
    if (days == null) {
      setError(t`Enter a whole number of days, or 0 to keep entries forever.`);
      return;
    }
    setError(null);
    if (days !== value) {
      updateSetting({ key: RETENTION_SETTING, value: days });
    }
  };

  return (
    <Box data-testid={`${RETENTION_SETTING}-setting`}>
      <SettingHeader
        id={RETENTION_SETTING}
        title={t`Days to keep entries`}
        description={t`Older entries are deleted every night, even while recording is off. Set it to 0 to keep them forever.`}
      />
      {settingDetails?.is_env_setting && settingDetails.env_name ? (
        <SetByEnvVar varName={settingDetails.env_name} />
      ) : (
        <TextInput
          id={RETENTION_SETTING}
          inputMode="numeric"
          value={localValue}
          error={error}
          onChange={(event) => setLocalValue(event.target.value)}
          onBlur={handleBlur}
        />
      )}
    </Box>
  );
}
