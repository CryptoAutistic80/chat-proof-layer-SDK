import type {
  PackManifest,
  PackReadinessSummary,
  PackSummaryResponse,
} from "../types.js";

type PackLike = PackSummaryResponse | PackManifest;

function asOptionalStatus(
  value: unknown,
): PackReadinessSummary["status"] | undefined {
  return value === "pass" || value === "warn" || value === "fail"
    ? value
    : undefined;
}

function asOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

export function selectPackReadiness(
  pack: PackLike,
): PackReadinessSummary | null {
  if (pack.pack_completeness_profile || pack.pack_completeness_status) {
    return {
      source: "pack_scoped",
      profile: pack.pack_completeness_profile,
      status: pack.pack_completeness_status,
      passCount: pack.pack_completeness_pass_count,
      warnCount: pack.pack_completeness_warn_count,
      failCount: pack.pack_completeness_fail_count,
    };
  }

  if (pack.completeness_profile || pack.completeness_status) {
    const legacyRecord = pack as Record<string, unknown>;
    return {
      source: "bundle_aggregate",
      profile: pack.completeness_profile,
      status: asOptionalStatus(legacyRecord.completeness_status),
      passCount: asOptionalNumber(legacyRecord.completeness_pass_count),
      warnCount: asOptionalNumber(legacyRecord.completeness_warn_count),
      failCount: asOptionalNumber(legacyRecord.completeness_fail_count),
    };
  }

  return null;
}
