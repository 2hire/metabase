import userEvent from "@testing-library/user-event";

import {
  findRequests,
  setupPropertiesEndpoints,
  setupSettingsEndpoints,
  setupUpdateSettingEndpoint,
} from "__support__/server-mocks";
import { mockSettings } from "__support__/settings";
import { renderWithProviders, screen } from "__support__/ui";
import { createMockState } from "metabase/redux/store/mocks";
import { createMockSettings } from "metabase-types/api/mocks";

import { McpAuditLogSettings } from "./McpAuditLogSettings";

const setup = async ({
  enabled = true,
  retentionDays = 90,
}: {
  enabled?: boolean;
  retentionDays?: number;
} = {}) => {
  const settings = createMockSettings({
    "mcp-audit-log-enabled?": enabled,
    "mcp-audit-log-retention-days": retentionDays,
  });

  setupPropertiesEndpoints(settings);
  setupSettingsEndpoints([]);
  setupUpdateSettingEndpoint();

  renderWithProviders(<McpAuditLogSettings />, {
    storeInitialState: createMockState({
      settings: mockSettings(settings),
    }),
  });

  return screen.findByLabelText("Days to keep entries");
};

describe("McpAuditLogSettings", () => {
  it("keeps the retention editable while recording is off", async () => {
    const input = await setup({ enabled: false });

    expect(input).toBeEnabled();
    expect(input).toHaveValue("90");
  });

  it("saves a whole number of days", async () => {
    const input = await setup();

    await userEvent.clear(input);
    await userEvent.type(input, "365");
    await userEvent.tab();

    const puts = await findRequests("PUT");
    expect(puts).toHaveLength(1);
    expect(puts[0].url).toContain("/setting/mcp-audit-log-retention-days");
    expect(puts[0].body).toEqual({ value: 365 });
  });

  it.each(["365.5", "1e3", "-1", ""])(
    "doesn't save %j and shows an error instead",
    async (value) => {
      const input = await setup();

      await userEvent.clear(input);
      if (value) {
        await userEvent.type(input, value);
      }
      await userEvent.tab();

      expect(
        await screen.findByText(
          "Enter a whole number of days, or 0 to keep entries forever.",
        ),
      ).toBeInTheDocument();
      expect(await findRequests("PUT")).toHaveLength(0);
    },
  );
});
