from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SHA256_PATTERN = "^sha256:[0-9a-f]{64}$"
MERKLE_ALGORITHM = "pl-merkle-sha256-v1"
FULL_PACKAGE_FORMAT = "pl-bundle-pkg-v1"
DISCLOSURE_PACKAGE_FORMAT = "pl-bundle-disclosure-pkg-v1"
EVIDENCE_PACK_FORMAT = "pl-evidence-pack-v1"
PACK_CURATION_PROFILE = "pack-rules-v1"

DATETIME_FIELDS = {
    "created_at",
    "occurred_at",
    "submitted_at",
    "due_at",
    "measured_at",
    "execution_start",
    "execution_end",
    "generated_at",
    "from",
    "to",
}

SCHEMA_FILES = (
    "capture_event.schema.json",
    "evidence_item.schema.json",
    "evidence_bundle.schema.json",
    "redacted_bundle.schema.json",
    "evidence_pack.schema.json",
    "completeness_report.schema.json",
    "schema_manifest.json",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate checked JSON schema artifacts.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that checked-in schema files already match the generated contract.",
    )
    return parser.parse_args()


def snake_case(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_workspace_version(repo_root: Path) -> str:
    cargo = read_text(repo_root / "Cargo.toml")
    match = re.search(
        r"^\[workspace\.package\]\s+version = \"([^\"]+)\"",
        cargo,
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError("failed to parse workspace.package.version from Cargo.toml")
    return match.group(1)


def read_core_source(repo_root: Path) -> str:
    return read_text(repo_root / "crates" / "core" / "src" / "schema" / "mod.rs")


def read_vault_source(repo_root: Path) -> str:
    return read_text(repo_root / "crates" / "vault" / "src" / "main.rs")


def parse_const(source: str, name: str) -> str:
    match = re.search(
        rf"pub const {re.escape(name)}: &str = \"([^\"]+)\";",
        source,
    )
    if match is None:
        raise RuntimeError(f"failed to parse {name} from schema/mod.rs")
    return match.group(1)


def extract_block(source: str, header: str) -> str:
    start = source.find(header)
    if start == -1:
        raise RuntimeError(f"failed to find block header {header!r}")
    brace_start = source.find("{", start)
    if brace_start == -1:
        raise RuntimeError(f"failed to find opening brace for {header!r}")

    depth = 0
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace_start + 1 : index]
    raise RuntimeError(f"failed to find closing brace for {header!r}")


def parse_actor_roles(source: str) -> list[str]:
    body = extract_block(source, "pub enum ActorRole")
    roles: list[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        roles.append(snake_case(line))
    if not roles:
        raise RuntimeError("no actor roles found in schema/mod.rs")
    return roles


def parse_struct_fields(source: str) -> dict[str, list[tuple[str, str]]]:
    structs: dict[str, list[tuple[str, str]]] = {}
    pattern = re.compile(r"pub struct (\w+)\s*\{", re.MULTILINE)
    for match in pattern.finditer(source):
        name = match.group(1)
        body = extract_block(source[match.start() :], f"pub struct {name}")
        fields: list[tuple[str, str]] = []
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            field_match = re.match(r"pub (\w+): ([^,]+),$", line)
            if field_match is None:
                continue
            fields.append((field_match.group(1), field_match.group(2).strip()))
        structs[name] = fields
    return structs


def parse_evidence_variants(source: str) -> list[tuple[str, str]]:
    body = extract_block(source, "pub enum EvidenceItem")
    variants: list[tuple[str, str]] = []
    for raw_line in body.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        match = re.match(r"(\w+)\((\w+)\)$", line)
        if match is None:
            continue
        variants.append((snake_case(match.group(1)), match.group(2)))
    if not variants:
        raise RuntimeError("no evidence item variants found in schema/mod.rs")
    return variants


def parse_pack_types(source: str) -> list[str]:
    block = extract_block(source, "fn normalize_pack_type")
    pack_types = sorted(set(re.findall(r"\"([a-z0-9_]+)\" =>", block)))
    return pack_types


def unwrap_option(rust_type: str) -> tuple[bool, str]:
    if rust_type.startswith("Option<") and rust_type.endswith(">"):
        return True, rust_type[len("Option<") : -1].strip()
    return False, rust_type


def json_pointer_map_schema(value_schema: dict[str, object] | bool) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": value_schema,
    }


def field_schema(field_name: str, rust_type: str, defs_prefix: str = "#/$defs/") -> tuple[dict[str, object] | bool, bool]:
    optional, inner_type = unwrap_option(rust_type)
    required = not optional and inner_type != "Value"

    if field_name == "metadata" or field_name == "parameters" or inner_type == "Value":
        return True, False
    if inner_type == "TokenUsage":
        return {"$ref": f"{defs_prefix}tokenUsage"}, False
    if inner_type == "DateRange":
        return {"$ref": f"{defs_prefix}dateRange"}, False
    if inner_type == "MetricSummary":
        return {"$ref": f"{defs_prefix}metricSummary"}, False
    if inner_type == "GroupMetricSummary":
        return {"$ref": f"{defs_prefix}groupMetricSummary"}, False
    if inner_type == "String":
        if "commitment" in field_name or field_name == "digest":
            return {"$ref": f"{defs_prefix}sha256Digest"}, required
        schema: dict[str, object] = {"type": "string"}
        if field_name in DATETIME_FIELDS:
            schema["format"] = "date-time"
        return schema, required
    if inner_type == "u64" or inner_type == "usize":
        return {"type": "integer", "minimum": 0}, required
    if inner_type == "bool":
        return {"type": "boolean"}, required
    if inner_type == "Vec<String>":
        return {"type": "array", "items": {"type": "string"}}, required
    if inner_type == "Vec<MetricSummary>":
        return {"type": "array", "items": {"$ref": f"{defs_prefix}metricSummary"}}, required
    if inner_type == "Vec<GroupMetricSummary>":
        return {
            "type": "array",
            "items": {"$ref": f"{defs_prefix}groupMetricSummary"},
        }, required
    raise RuntimeError(f"unsupported field type {rust_type!r} for {field_name}")


def build_shared_defs() -> dict[str, object]:
    return {
        "sha256Digest": {
            "type": "string",
            "pattern": SHA256_PATTERN,
        },
        "tokenUsage": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "input_tokens": {"type": "integer", "minimum": 0},
                "output_tokens": {"type": "integer", "minimum": 0},
                "total_tokens": {"type": "integer", "minimum": 0},
            },
        },
        "dateRange": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "start": {"type": "string"},
                "end": {"type": "string"},
            },
        },
        "metricSummary": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "value"],
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "string"},
                "unit": {"type": "string"},
                "methodology": {"type": "string"},
            },
        },
        "groupMetricSummary": {
            "type": "object",
            "additionalProperties": False,
            "required": ["group"],
            "properties": {
                "group": {"type": "string"},
                "metrics": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/metricSummary"},
                },
            },
        },
    }


def build_item_variant_schema(
    item_type: str,
    struct_name: str,
    structs: dict[str, list[tuple[str, str]]],
) -> dict[str, object]:
    if struct_name not in structs:
        raise RuntimeError(f"missing struct definition for {struct_name}")

    data_properties: dict[str, object] = {}
    required_fields: list[str] = []
    for field_name, rust_type in structs[struct_name]:
        schema, required = field_schema(field_name, rust_type)
        data_properties[field_name] = schema
        if required:
            required_fields.append(field_name)

    data: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": data_properties,
    }
    if required_fields:
        data["required"] = required_fields

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "type": {"const": item_type},
            "data": data,
        },
        "required": ["type", "data"],
    }


def build_capture_event_schema(
    roles: list[str],
    structs: dict[str, list[tuple[str, str]]],
) -> dict[str, object]:
    compliance_profile_properties: dict[str, object] = {}
    for field_name, rust_type in structs["ComplianceProfile"]:
        schema, _ = field_schema(field_name, rust_type)
        compliance_profile_properties[field_name] = schema

    context_properties: dict[str, object] = {}
    for field_name, rust_type in structs["EvidenceContext"]:
        schema, _ = field_schema(field_name, rust_type)
        context_properties[field_name] = schema

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/capture_event.schema.json",
        "title": "Capture Event",
        "description": "v1.0 capture input accepted by proofctl and the proof service.",
        "type": "object",
        "additionalProperties": False,
        "required": ["actor", "subject", "items"],
        "properties": {
            "actor": {
                "type": "object",
                "additionalProperties": False,
                "required": ["issuer", "app_id", "env", "signing_key_id"],
                "properties": {
                    "issuer": {"type": "string", "minLength": 1},
                    "app_id": {"type": "string", "minLength": 1},
                    "env": {"type": "string", "minLength": 1},
                    "signing_key_id": {"type": "string", "minLength": 1},
                    "role": {"type": "string", "enum": roles},
                    "organization_id": {"type": "string"},
                },
            },
            "subject": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "request_id": {"type": "string"},
                    "thread_id": {"type": "string"},
                    "user_ref": {"type": "string"},
                    "system_id": {"type": "string"},
                    "model_id": {"type": "string"},
                    "deployment_id": {"type": "string"},
                    "version": {"type": "string"},
                },
            },
            "compliance_profile": {
                "type": "object",
                "additionalProperties": False,
                "properties": compliance_profile_properties,
            },
            "context": {
                "type": "object",
                "additionalProperties": False,
                "properties": context_properties,
            },
            "items": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "./evidence_item.schema.json"},
            },
            "policy": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "redactions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "encryption": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "enabled": {"type": "boolean"},
                        },
                    },
                    "retention_class": {"type": "string"},
                },
            },
        },
    }


def build_evidence_item_schema(
    variants: list[tuple[str, str]],
    structs: dict[str, list[tuple[str, str]]],
) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/evidence_item.schema.json",
        "title": "Evidence Item",
        "description": "Typed evidence item stored inside a v1.0 EvidenceBundle.",
        "oneOf": [
            build_item_variant_schema(item_type, struct_name, structs)
            for item_type, struct_name in variants
        ],
        "$defs": build_shared_defs(),
    }


def build_bundle_schema(
    bundle_version: str,
    canonicalization: str,
    hash_algorithm: str,
    default_bundle_root_algorithm: str,
    supported_bundle_root_algorithms: list[str],
    signature_algorithm: str,
    signature_format: str,
) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/evidence_bundle.schema.json",
        "title": "Evidence Bundle",
        "description": "Signed v1.0 bundle emitted by proofctl and the proof service.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bundle_version",
            "bundle_id",
            "created_at",
            "actor",
            "subject",
            "items",
            "artefacts",
            "policy",
            "integrity",
        ],
        "properties": {
            "bundle_version": {"const": bundle_version},
            "bundle_id": {"type": "string", "minLength": 1},
            "created_at": {"type": "string", "format": "date-time"},
            "actor": {"$ref": "./capture_event.schema.json#/properties/actor"},
            "subject": {"$ref": "./capture_event.schema.json#/properties/subject"},
            "compliance_profile": {
                "$ref": "./capture_event.schema.json#/properties/compliance_profile"
            },
            "context": {"$ref": "./capture_event.schema.json#/properties/context"},
            "items": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "./evidence_item.schema.json"},
            },
            "artefacts": {
                "type": "array",
                "items": {"$ref": "#/$defs/artefactRef"},
            },
            "policy": {"$ref": "./capture_event.schema.json#/properties/policy"},
            "integrity": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "canonicalization",
                    "hash",
                    "header_digest",
                    "bundle_root_algorithm",
                    "bundle_root",
                    "signature",
                ],
                "properties": {
                    "canonicalization": {"const": canonicalization},
                    "hash": {"const": hash_algorithm},
                    "header_digest": {"$ref": "#/$defs/sha256Digest"},
                    "bundle_root_algorithm": {
                        "type": "string",
                        "enum": supported_bundle_root_algorithms,
                        "default": default_bundle_root_algorithm,
                    },
                    "bundle_root": {"$ref": "#/$defs/sha256Digest"},
                    "signature": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["format", "alg", "kid", "value"],
                        "properties": {
                            "format": {"const": signature_format},
                            "alg": {"const": signature_algorithm},
                            "kid": {"type": "string", "minLength": 1},
                            "value": {"type": "string", "minLength": 1},
                        },
                    },
                },
            },
            "timestamp": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "token_base64"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1},
                    "provider": {"type": "string", "minLength": 1},
                    "token_base64": {"type": "string", "minLength": 1},
                },
            },
            "receipt": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "body"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1},
                    "provider": {"type": "string", "minLength": 1},
                    "body": True,
                },
            },
        },
        "$defs": {
            "sha256Digest": {"type": "string", "pattern": SHA256_PATTERN},
            "artefactRef": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "digest", "size", "content_type"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "digest": {"$ref": "#/$defs/sha256Digest"},
                    "size": {"type": "integer", "minimum": 0},
                    "content_type": {"type": "string", "minLength": 1},
                },
            },
        },
    }


def build_redacted_bundle_schema(
    bundle_version: str,
    canonicalization: str,
    hash_algorithm: str,
    disclosure_bundle_root_algorithms: list[str],
    signature_algorithm: str,
    signature_format: str,
) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/redacted_bundle.schema.json",
        "title": "Redacted Evidence Bundle",
        "description": "Selective-disclosure bundle carrying Merkle inclusion proofs for a v2, v3, or v4 evidence bundle.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bundle_version",
            "bundle_id",
            "created_at",
            "actor",
            "subject",
            "policy",
            "integrity",
            "total_items",
            "total_artefacts",
            "header_proof",
            "disclosed_items",
            "disclosed_artefacts",
        ],
        "properties": {
            "bundle_version": {"const": bundle_version},
            "bundle_id": {"type": "string", "minLength": 1},
            "created_at": {"type": "string", "format": "date-time"},
            "actor": {"$ref": "./capture_event.schema.json#/properties/actor"},
            "subject": {"$ref": "./capture_event.schema.json#/properties/subject"},
            "compliance_profile": {
                "$ref": "./capture_event.schema.json#/properties/compliance_profile"
            },
            "context": {"$ref": "./capture_event.schema.json#/properties/context"},
            "policy": {"$ref": "./capture_event.schema.json#/properties/policy"},
            "integrity": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "canonicalization",
                    "hash",
                    "header_digest",
                    "bundle_root_algorithm",
                    "bundle_root",
                    "signature",
                ],
                "properties": {
                    "canonicalization": {"const": canonicalization},
                    "hash": {"const": hash_algorithm},
                    "header_digest": {"$ref": "#/$defs/sha256Digest"},
                    "bundle_root_algorithm": {
                        "type": "string",
                        "enum": disclosure_bundle_root_algorithms,
                    },
                    "bundle_root": {"$ref": "#/$defs/sha256Digest"},
                    "signature": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["format", "alg", "kid", "value"],
                        "properties": {
                            "format": {"const": signature_format},
                            "alg": {"const": signature_algorithm},
                            "kid": {"type": "string", "minLength": 1},
                            "value": {"type": "string", "minLength": 1},
                        },
                    },
                },
            },
            "timestamp": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "token_base64"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1},
                    "provider": {"type": "string", "minLength": 1},
                    "token_base64": {"type": "string", "minLength": 1},
                },
            },
            "receipt": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "body"],
                "properties": {
                    "kind": {"type": "string", "minLength": 1},
                    "provider": {"type": "string", "minLength": 1},
                    "body": True,
                },
            },
            "total_items": {"type": "integer", "minimum": 0},
            "total_artefacts": {"type": "integer", "minimum": 0},
            "header_proof": {"$ref": "#/$defs/inclusionProof"},
            "disclosed_items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["index", "proof"],
                    "properties": {
                        "index": {"type": "integer", "minimum": 0},
                        "item": {"$ref": "./evidence_item.schema.json"},
                        "field_redacted_item": {"$ref": "#/$defs/fieldRedactedItem"},
                        "proof": {"$ref": "#/$defs/inclusionProof"},
                    },
                },
            },
            "disclosed_artefacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["index", "meta", "proof"],
                    "properties": {
                        "index": {"type": "integer", "minimum": 0},
                        "meta": {"$ref": "#/$defs/artefactRef"},
                        "proof": {"$ref": "#/$defs/inclusionProof"},
                    },
                },
            },
        },
        "$defs": {
            "sha256Digest": {"type": "string", "pattern": SHA256_PATTERN},
            "artefactRef": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "digest", "size", "content_type"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "digest": {"$ref": "#/$defs/sha256Digest"},
                    "size": {"type": "integer", "minimum": 0},
                    "content_type": {"type": "string", "minLength": 1},
                },
            },
            "proofStep": {
                "type": "object",
                "additionalProperties": False,
                "required": ["sibling", "position"],
                "properties": {
                    "sibling": {"$ref": "#/$defs/sha256Digest"},
                    "position": {"type": "string", "enum": ["left", "right"]},
                },
            },
            "inclusionProof": {
                "type": "object",
                "additionalProperties": False,
                "required": ["algorithm", "root", "leaf", "index", "path"],
                "properties": {
                    "algorithm": {"const": MERKLE_ALGORITHM},
                    "root": {"$ref": "#/$defs/sha256Digest"},
                    "leaf": {"$ref": "#/$defs/sha256Digest"},
                    "index": {"type": "integer", "minimum": 0},
                    "path": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/proofStep"},
                    },
                },
            },
            "fieldRedactedItem": {
                "type": "object",
                "additionalProperties": False,
                "required": ["item_type"],
                "properties": {
                    "item_type": {"type": "string", "minLength": 1},
                    "revealed_data": json_pointer_map_schema(True),
                    "field_digests": json_pointer_map_schema(
                        {"type": "string", "pattern": SHA256_PATTERN}
                    ),
                    "redacted_fields": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "container_kinds": json_pointer_map_schema({"type": "string"}),
                    "revealed_paths": json_pointer_map_schema(True),
                    "path_digests": json_pointer_map_schema(
                        {"type": "string", "pattern": SHA256_PATTERN}
                    ),
                    "redacted_paths": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
    }


def build_evidence_pack_schema(pack_types: list[str]) -> dict[str, object]:
    properties: dict[str, object] = {
        "pack_id": {"type": "string", "minLength": 1},
        "pack_type": {
            "type": "string",
            "minLength": 1,
        },
        "curation_profile": {"type": "string", "const": PACK_CURATION_PROFILE},
        "generated_at": {"type": "string", "format": "date-time"},
        "bundle_format": {"type": "string", "enum": ["full", "disclosure"]},
        "disclosure_policy": {"type": "string", "minLength": 1},
        "completeness_profile": {"type": "string", "enum": ["annex_iv_governance_v1"]},
        "completeness_pass_count": {"type": "integer", "minimum": 0},
        "completeness_warn_count": {"type": "integer", "minimum": 0},
        "completeness_fail_count": {"type": "integer", "minimum": 0},
        "system_id": {"type": "string", "minLength": 1},
        "from": {"type": "string", "format": "date-time"},
        "to": {"type": "string", "format": "date-time"},
        "bundle_ids": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
        "bundles": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "bundle_id",
                    "created_at",
                    "actor_role",
                    "retention_class",
                    "item_types",
                    "matched_rules",
                ],
                "properties": {
                    "bundle_id": {"type": "string", "minLength": 1},
                    "created_at": {"type": "string", "format": "date-time"},
                    "actor_role": {"type": "string", "minLength": 1},
                    "system_id": {"type": "string", "minLength": 1},
                    "model_id": {"type": "string", "minLength": 1},
                    "retention_class": {"type": "string", "minLength": 1},
                    "item_types": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1},
                    },
                    "bundle_format": {"type": "string", "enum": ["full", "disclosure"]},
                    "package_name": {"type": "string", "minLength": 1},
                    "disclosed_item_indices": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0},
                    },
                    "disclosed_item_types": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "disclosed_item_field_redactions": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                        },
                    },
                    "disclosed_artefact_indices": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0},
                    },
                    "disclosed_artefact_names": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "disclosed_artefact_bytes_included": {"type": "boolean"},
                    "obligation_refs": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                    "completeness_status": {
                        "type": "string",
                        "enum": ["pass", "warn", "fail"],
                    },
                    "matched_rules": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
    }
    if pack_types:
        properties["pack_type"]["enum"] = pack_types

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/evidence_pack.schema.json",
        "title": "Evidence Pack",
        "description": "Manifest embedded in vault-generated pl-evidence-pack-v1 archives.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "pack_id",
            "pack_type",
            "curation_profile",
            "generated_at",
            "bundle_ids",
            "bundles",
        ],
        "properties": properties,
    }


def build_completeness_report_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/completeness_report.schema.json",
        "title": "Completeness Report",
        "description": "Advisory structural readiness report for machine-assessed governance completeness profiles.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "profile",
            "status",
            "bundle_id",
            "pass_count",
            "warn_count",
            "fail_count",
            "rules",
        ],
        "properties": {
            "profile": {"type": "string", "enum": ["annex_iv_governance_v1"]},
            "status": {"type": "string", "enum": ["pass", "warn", "fail"]},
            "bundle_id": {"type": "string", "minLength": 1},
            "system_id": {"type": "string", "minLength": 1},
            "pass_count": {"type": "integer", "minimum": 0},
            "warn_count": {"type": "integer", "minimum": 0},
            "fail_count": {"type": "integer", "minimum": 0},
            "rules": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "rule_id",
                        "item_type",
                        "obligation_ref",
                        "status",
                        "present_count",
                        "complete_count",
                        "summary",
                    ],
                    "properties": {
                        "rule_id": {"type": "string", "minLength": 1},
                        "item_type": {"type": "string", "minLength": 1},
                        "obligation_ref": {"type": "string", "minLength": 1},
                        "status": {"type": "string", "enum": ["pass", "warn", "fail"]},
                        "present_count": {"type": "integer", "minimum": 0},
                        "complete_count": {"type": "integer", "minimum": 0},
                        "evaluated_item_indices": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 0},
                        },
                        "missing_fields": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                        },
                        "summary": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
    }


def build_schema_manifest(
    release_version: str,
    bundle_version: str,
    canonicalization: str,
    hash_algorithm: str,
    default_bundle_root_algorithm: str,
    supported_bundle_root_algorithms: list[str],
    actor_roles: list[str],
    evidence_item_types: list[str],
    pack_types: list[str],
) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.dev/schemas/schema_manifest.json",
        "title": "Proof Layer Schema Manifest",
        "release_version": release_version,
        "bundle_version": bundle_version,
        "canonicalization": canonicalization,
        "hash_algorithm": hash_algorithm,
        "default_bundle_root_algorithm": default_bundle_root_algorithm,
        "supported_bundle_root_algorithms": supported_bundle_root_algorithms,
        "package_formats": {
            "bundle": FULL_PACKAGE_FORMAT,
            "disclosure_bundle": DISCLOSURE_PACKAGE_FORMAT,
            "evidence_pack": EVIDENCE_PACK_FORMAT,
        },
        "curation_profile": PACK_CURATION_PROFILE,
        "actor_roles": actor_roles,
        "evidence_item_types": evidence_item_types,
        "pack_types": pack_types,
        "schema_files": {
            "capture_event": "schemas/capture_event.schema.json",
            "evidence_item": "schemas/evidence_item.schema.json",
            "evidence_bundle": "schemas/evidence_bundle.schema.json",
            "redacted_bundle": "schemas/redacted_bundle.schema.json",
            "evidence_pack": "schemas/evidence_pack.schema.json",
            "completeness_report": "schemas/completeness_report.schema.json",
        },
    }


def build_wrapper_schema() -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://proof-layer.local/docs/proof_bundle.schema.json",
        "title": "Proof Bundle Schema Reference",
        "description": "Compatibility wrapper pointing at the canonical v1.0 evidence bundle schema in ../schemas.",
        "allOf": [{"$ref": "../schemas/evidence_bundle.schema.json"}],
    }


def build_expected_schema_files(repo_root: Path) -> dict[Path, str]:
    core_source = read_core_source(repo_root)
    vault_source = read_vault_source(repo_root)
    structs = parse_struct_fields(core_source)
    roles = parse_actor_roles(core_source)
    variants = parse_evidence_variants(core_source)
    pack_types = parse_pack_types(vault_source)

    release_version = read_workspace_version(repo_root)
    bundle_version = parse_const(core_source, "BUNDLE_VERSION")
    canonicalization = parse_const(core_source, "CANONICALIZATION_ALGORITHM")
    hash_algorithm = parse_const(core_source, "HASH_ALGORITHM")
    legacy_algorithm = parse_const(core_source, "LEGACY_BUNDLE_ROOT_ALGORITHM")
    algorithm_v2 = parse_const(core_source, "BUNDLE_ROOT_ALGORITHM_V2")
    algorithm_v3 = parse_const(core_source, "BUNDLE_ROOT_ALGORITHM_V3")
    default_algorithm = parse_const(core_source, "BUNDLE_ROOT_ALGORITHM_V4")
    signature_algorithm = parse_const(core_source, "SIGNATURE_ALGORITHM")
    signature_format = parse_const(core_source, "SIGNATURE_FORMAT")

    evidence_item_types = [item_type for item_type, _ in variants]
    supported_bundle_root_algorithms = [
        legacy_algorithm,
        algorithm_v2,
        algorithm_v3,
        default_algorithm,
    ]

    schema_dir = repo_root / "schemas"
    docs_dir = repo_root / "docs"
    objects = {
        schema_dir / "capture_event.schema.json": build_capture_event_schema(roles, structs),
        schema_dir / "evidence_item.schema.json": build_evidence_item_schema(variants, structs),
        schema_dir / "evidence_bundle.schema.json": build_bundle_schema(
            bundle_version=bundle_version,
            canonicalization=canonicalization,
            hash_algorithm=hash_algorithm,
            default_bundle_root_algorithm=default_algorithm,
            supported_bundle_root_algorithms=supported_bundle_root_algorithms,
            signature_algorithm=signature_algorithm,
            signature_format=signature_format,
        ),
        schema_dir / "redacted_bundle.schema.json": build_redacted_bundle_schema(
            bundle_version=bundle_version,
            canonicalization=canonicalization,
            hash_algorithm=hash_algorithm,
            disclosure_bundle_root_algorithms=[algorithm_v2, algorithm_v3, default_algorithm],
            signature_algorithm=signature_algorithm,
            signature_format=signature_format,
        ),
        schema_dir / "evidence_pack.schema.json": build_evidence_pack_schema(pack_types),
        schema_dir / "completeness_report.schema.json": build_completeness_report_schema(),
        schema_dir / "schema_manifest.json": build_schema_manifest(
            release_version=release_version,
            bundle_version=bundle_version,
            canonicalization=canonicalization,
            hash_algorithm=hash_algorithm,
            default_bundle_root_algorithm=default_algorithm,
            supported_bundle_root_algorithms=supported_bundle_root_algorithms,
            actor_roles=roles,
            evidence_item_types=evidence_item_types,
            pack_types=pack_types,
        ),
        docs_dir / "proof_bundle.schema.json": build_wrapper_schema(),
    }

    return {
        path: json.dumps(payload, indent=2) + "\n"
        for path, payload in objects.items()
    }


def main() -> None:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    expected = build_expected_schema_files(repo_root)

    if args.check:
        mismatches = []
        for path, contents in expected.items():
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != contents:
                mismatches.append(path.relative_to(repo_root).as_posix())
        if mismatches:
            for path in mismatches:
                print(f"schema drift: {path}", file=sys.stderr)
            raise SystemExit(1)
        print(json.dumps({"checked": [path.name for path in expected]}, indent=2))
        return

    for path, contents in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    print(json.dumps({"written": [path.name for path in expected]}, indent=2))


if __name__ == "__main__":
    main()
