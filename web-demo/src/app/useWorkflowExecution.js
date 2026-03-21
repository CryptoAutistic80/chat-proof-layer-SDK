import { useCallback, useState } from "react";
import {
  attachTimestamp,
  anchorBundle,
  createBundle,
  createPack,
  downloadPackExport,
  fetchBundle,
  fetchBundleArtefact,
  fetchDemoProviderResponse,
  fetchPackManifest,
  fetchSystemSummary,
  formatBytes,
  previewDisclosure,
  verifyBundle,
  verifyReceipt,
  verifyTimestamp
} from "../lib/vaultApi";
import { decodeJsonBytes } from "../lib/captureBuilders";
import { defaultTemplateName } from "../lib/presets";

/**
 * Encapsulates workflow execution operations: bundle lifecycle,
 * preview, export, verification. Extracted from DemoContext.
 */
export function useWorkflowExecution(draftRef, vaultConfigRef, appendActivity) {
  const [isRunning, setIsRunning] = useState(false);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  function buildTemplateRequest(templateProfile, selectedGroups, templateName) {
    return {
      profile: templateProfile,
      name: templateName?.trim() || defaultTemplateName(templateProfile),
      redaction_groups: selectedGroups,
      redacted_fields_by_item_type: {}
    };
  }

  const fetchArtefacts = useCallback(async (bundleId, bundleArtefacts) => {
    const draft = draftRef.current;
    const files = await Promise.all(
      (bundleArtefacts ?? []).map(async (artefact) => {
        const response = await fetchBundleArtefact(
          draft.serviceUrl,
          draft.apiKey,
          bundleId,
          artefact.name
        );
        return {
          name: artefact.name,
          bytes: new Uint8Array(response.buffer),
          contentType: response.contentType ?? artefact.content_type
        };
      })
    );

    const parsed = {};
    for (const file of files) {
      if (file.name.endsWith(".json")) {
        try {
          parsed[file.name] = decodeJsonBytes(file.bytes.buffer);
        } catch {
          // ignore
        }
      } else if (file.name.endsWith(".md")) {
        parsed[file.name] = new TextDecoder().decode(file.bytes);
      }
    }
    return { files, parsed };
  }, [draftRef]);

  const verifyCreatedBundle = useCallback(async (bundle, artefacts) => {
    const publicKeyPem = vaultConfigRef.current?.signing?.public_key_pem;
    if (!publicKeyPem) {
      return { valid: false, message: "No public verify key.", artefacts_verified: 0 };
    }
    const draft = draftRef.current;
    return verifyBundle(draft.serviceUrl, draft.apiKey, {
      bundle,
      artefacts: artefacts.map((a) => ({ name: a.name, data_base64: a.data_base64 })),
      public_key_pem: publicKeyPem
    });
  }, [draftRef, vaultConfigRef]);

  const previewFor = useCallback(async (bundleId, systemId, options = {}) => {
    const draft = draftRef.current;
    const templateProfile = options.templateProfile ?? draft.templateProfile;
    const selectedGroups = options.selectedGroups ?? draft.selectedGroups;
    const packType = options.packType ?? null;
    const payload = {
      bundle_id: bundleId,
      pack_type: packType,
      disclosure_template: buildTemplateRequest(templateProfile, selectedGroups, draft.templateName)
    };
    const response = await previewDisclosure(draft.serviceUrl, draft.apiKey, payload);
    const itemCount = Array.isArray(response?.disclosed_item_indices) ? response.disclosed_item_indices.length : 0;
    const artefactCount = Array.isArray(response?.disclosed_artefact_names) ? response.disclosed_artefact_names.length : 0;
    appendActivity("Disclosure preview ready", `${itemCount} items \u00B7 ${artefactCount} artefacts`, "accent");
    return response;
  }, [draftRef, appendActivity]);

  const exportFor = useCallback(async (bundleId, systemId, options = {}) => {
    const draft = draftRef.current;
    const bundleFormat = options.bundleFormat ?? draft.bundleFormat;
    const templateProfile = options.templateProfile ?? draft.templateProfile;
    const selectedGroups = options.selectedGroups ?? draft.selectedGroups;
    const packType = options.packType ?? null;
    const requestBody = {
      pack_type: packType,
      system_id: systemId,
      bundle_format: bundleFormat
    };
    if (bundleFormat === "disclosure") {
      requestBody.disclosure_template = buildTemplateRequest(templateProfile, selectedGroups, draft.templateName);
    }
    const packSummary = await createPack(draft.serviceUrl, draft.apiKey, requestBody);
    const packManifest = await fetchPackManifest(draft.serviceUrl, draft.apiKey, packSummary.pack_id);
    const exportPayload = await downloadPackExport(draft.serviceUrl, draft.apiKey, packSummary.pack_id);
    const blob = new Blob([exportPayload.buffer], { type: exportPayload.contentType ?? "application/gzip" });
    const downloadInfo = {
      url: typeof URL.createObjectURL === "function" ? URL.createObjectURL(blob) : "",
      fileName: `${bundleFormat === "disclosure" ? "disclosure" : "full"}-${bundleId}.pack`,
      size: blob.size
    };
    appendActivity("Pack exported", `${packSummary.bundle_count} bundle(s) \u00B7 ${formatBytes(blob.size)}`, "good");
    return { packSummary, packManifest, downloadInfo };
  }, [draftRef, appendActivity]);

  const runBundleLifecycle = useCallback(async (step) => {
    const draft = draftRef.current;
    const vaultConfig = vaultConfigRef.current;
    const createMeta = await createBundle(draft.serviceUrl, draft.apiKey, step.createPayload);
    appendActivity("Bundle sealed", `${step.label} \u00B7 ${createMeta.bundle_id}`, "good");

    let bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
    const verifyResponse = await verifyCreatedBundle(bundle, step.createPayload.artefacts);
    appendActivity(
      verifyResponse.valid ? "Bundle verified" : "Bundle verification warning",
      verifyResponse.valid ? `${step.label} verified.` : verifyResponse.message,
      verifyResponse.valid ? "good" : "warn"
    );

    let timestampResponse = null;
    let timestampVerification = null;
    if (draft.attachTimestamp && vaultConfig?.timestamp?.enabled) {
      try {
        timestampResponse = await attachTimestamp(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
        timestampVerification = await verifyTimestamp(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
      } catch (error) {
        timestampVerification = { valid: false, message: error instanceof Error ? error.message : String(error) };
      }
    }

    let anchorResponse = null;
    let receiptVerification = null;
    if (draft.attachTransparency && vaultConfig?.transparency?.enabled && timestampResponse) {
      try {
        anchorResponse = await anchorBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
        receiptVerification = await verifyReceipt(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
      } catch (error) {
        receiptVerification = { valid: false, message: error instanceof Error ? error.message : String(error) };
      }
    }

    if (timestampResponse || anchorResponse) {
      bundle = await fetchBundle(draft.serviceUrl, draft.apiKey, createMeta.bundle_id);
    }

    return {
      ...step,
      bundleId: createMeta.bundle_id,
      createMeta,
      bundle,
      verifyResponse,
      timestampResponse,
      timestampVerification,
      anchorResponse,
      receiptVerification
    };
  }, [draftRef, vaultConfigRef, appendActivity, verifyCreatedBundle]);

  return {
    isRunning,
    setIsRunning,
    isPreviewing,
    setIsPreviewing,
    isExporting,
    setIsExporting,
    buildTemplateRequest,
    fetchArtefacts,
    verifyCreatedBundle,
    previewFor,
    exportFor,
    runBundleLifecycle
  };
}
