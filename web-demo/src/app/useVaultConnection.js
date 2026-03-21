import { useCallback, useState } from "react";
import {
  fetchVaultConfig,
  fetchDisclosureTemplates
} from "../lib/vaultApi";
import {
  DEFAULT_SERVICE_URL,
  defaultTemplateName,
  isProviderLiveEnabled
} from "../lib/presets";

/**
 * Manages the vault connection state: config, templates, connection errors.
 * Extracted from DemoContext to keep vault concerns isolated.
 */
export function useVaultConnection(draftRef, setDraft, appendActivity) {
  const [vaultConfig, setVaultConfig] = useState(null);
  const [templateCatalog, setTemplateCatalog] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [connectionError, setConnectionError] = useState("");

  function syncTemplateDefaults(catalog, nextDraft) {
    const templates = Array.isArray(catalog?.templates) ? catalog.templates : [];
    if (templates.length === 0) return nextDraft;
    const selected =
      templates.find((t) => t.profile === nextDraft.templateProfile) ?? templates[0];
    return {
      ...nextDraft,
      templateProfile: selected.profile,
      templateName: nextDraft.templateName?.trim()
        ? nextDraft.templateName
        : defaultTemplateName(selected.profile),
      selectedGroups:
        nextDraft.selectedGroups.length > 0
          ? nextDraft.selectedGroups
          : selected.default_redaction_groups ?? []
    };
  }

  function canUseLiveMode(config, provider, providerApiKey) {
    return isProviderLiveEnabled(config, provider) || Boolean(providerApiKey?.trim());
  }

  const refreshVaultCapabilities = useCallback(async () => {
    setIsRefreshing(true);
    setConnectionError("");
    const draft = draftRef.current;
    try {
      const [configResponse, templateResponse] = await Promise.all([
        fetchVaultConfig(draft.serviceUrl, draft.apiKey),
        fetchDisclosureTemplates(draft.serviceUrl, draft.apiKey)
      ]);
      setVaultConfig(configResponse);
      setTemplateCatalog(templateResponse);
      setDraft((current) => {
        const synced = syncTemplateDefaults(templateResponse, current);
        if (!canUseLiveMode(configResponse, synced.provider, synced.providerApiKey) && synced.mode === "live") {
          return { ...synced, mode: "synthetic" };
        }
        return synced;
      });
      appendActivity(
        "Vault connected",
        `${configResponse.service.addr} \u00B7 ${configResponse.signing.ephemeral ? "ephemeral signer" : "configured signer"}`,
        "good"
      );
      return configResponse;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setConnectionError(message);
      appendActivity("Vault connection failed", message, "bad");
      return null;
    } finally {
      setIsRefreshing(false);
    }
  }, [draftRef, setDraft, appendActivity]);

  return {
    vaultConfig,
    templateCatalog,
    isRefreshing,
    connectionError,
    refreshVaultCapabilities,
    syncTemplateDefaults,
    canUseLiveMode
  };
}
