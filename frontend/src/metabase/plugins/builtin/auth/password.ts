import { PLUGIN_AUTH_PROVIDERS } from "metabase/plugins";
import MetabaseSettings from "metabase/utils/settings";

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  const passwordProvider = {
    name: "password",
    // circular dependencies
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    Button: require("metabase/auth/components/PasswordButton").PasswordButton,
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    Panel: require("metabase/auth/components/PasswordPanel").PasswordPanel,
  };

  // 2hire: hide email/password login when it's disabled (Google Sign-In only)
  if (!MetabaseSettings.isPasswordLoginEnabled()) {
    return providers;
  }

  return [...providers, passwordProvider];
});
