import test from "node:test";
import assert from "node:assert/strict";
import {
  createDisclosurePolicy,
  createDisclosurePolicyTemplate,
  disclosurePolicyTemplateNames,
  disclosureRedactionGroups
} from "../dist/index.js";

test("disclosure policy template exports remain stable", () => {
  assert.deepEqual(disclosurePolicyTemplateNames, [
    "regulator_minimum",
    "annex_iv_redacted",
    "incident_summary",
    "runtime_minimum",
    "privacy_review"
  ]);
  assert.deepEqual(disclosureRedactionGroups, [
    "commitments",
    "metadata",
    "parameters",
    "operational_metrics"
  ]);
});

test("createDisclosurePolicyTemplate builds runtime minimum selectors", () => {
  const policy = createDisclosurePolicyTemplate("runtime_minimum");

  assert.equal(policy.name, "runtime_minimum");
  assert.deepEqual(policy.allowed_item_types, [
    "llm_interaction",
    "tool_call",
    "retrieval",
    "policy_decision",
    "human_oversight"
  ]);
  assert.deepEqual(policy.redacted_fields_by_item_type?.llm_interaction, [
    "input_commitment",
    "retrieval_commitment",
    "output_commitment",
    "tool_outputs_commitment",
    "trace_commitment",
    "/parameters",
    "/token_usage",
    "/latency_ms",
    "/trace_semconv_version"
  ]);
  assert.deepEqual(policy.redacted_fields_by_item_type?.tool_call, [
    "input_commitment",
    "output_commitment"
  ]);
});

test("createDisclosurePolicy merges template groups with explicit selectors", () => {
  const policy = createDisclosurePolicy({
    name: "custom_incident",
    allowedItemTypes: ["authority_submission"],
    redactionGroups: ["commitments", "metadata"],
    redactedFieldsByItemType: {
      authority_submission: ["/metadata/submission_case_id"]
    }
  });

  assert.deepEqual(policy.redacted_fields_by_item_type, {
    authority_submission: [
      "document_commitment",
      "/metadata",
      "/metadata/submission_case_id"
    ]
  });
});

test("createDisclosurePolicyTemplate incident summary includes authority-reporting item types", () => {
  const policy = createDisclosurePolicyTemplate("incident_summary");

  assert.deepEqual(policy.allowed_item_types, [
    "incident_report",
    "authority_notification",
    "authority_submission",
    "reporting_deadline",
    "regulator_correspondence",
    "risk_assessment",
    "policy_decision",
    "human_oversight"
  ]);
});
