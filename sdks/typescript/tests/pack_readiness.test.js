import test from "node:test";
import assert from "node:assert/strict";
import { selectPackReadiness } from "../dist/index.js";

test("selectPackReadiness prefers pack-scoped completeness fields", () => {
  const readiness = selectPackReadiness({
    pack_id: "P1",
    pack_type: "annex_iv",
    created_at: "2026-03-21T00:00:00Z",
    bundle_format: "full",
    bundle_count: 8,
    bundle_ids: ["B1"],
    completeness_profile: "annex_iv_governance_v1",
    completeness_status: "fail",
    pack_completeness_profile: "annex_iv_governance_v1",
    pack_completeness_status: "pass",
    pack_completeness_pass_count: 8,
    pack_completeness_warn_count: 0,
    pack_completeness_fail_count: 0,
  });

  assert.deepEqual(readiness, {
    source: "pack_scoped",
    profile: "annex_iv_governance_v1",
    status: "pass",
    passCount: 8,
    warnCount: 0,
    failCount: 0,
  });
});

test("selectPackReadiness falls back to legacy bundle aggregate completeness", () => {
  const readiness = selectPackReadiness({
    pack_id: "P2",
    pack_type: "runtime_logs",
    curation_profile: "pack-rules-v1",
    generated_at: "2026-03-21T00:00:00Z",
    bundle_format: "full",
    bundle_ids: ["B1"],
    bundles: [],
    completeness_profile: "gpai_provider_v1",
    completeness_status: "warn",
    completeness_pass_count: 1,
    completeness_warn_count: 1,
    completeness_fail_count: 0,
  });

  assert.deepEqual(readiness, {
    source: "bundle_aggregate",
    profile: "gpai_provider_v1",
    status: "warn",
    passCount: 1,
    warnCount: 1,
    failCount: 0,
  });
});

test("selectPackReadiness returns null when no completeness fields are present", () => {
  const readiness = selectPackReadiness({
    pack_id: "P3",
    pack_type: "runtime_logs",
    created_at: "2026-03-21T00:00:00Z",
    bundle_format: "full",
    bundle_count: 0,
    bundle_ids: [],
  });

  assert.equal(readiness, null);
});
