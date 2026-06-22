"""
STIX 2.1 JSON export for filtered attack chains (MVP: attack-patterns, groupings, relationships).
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

import pandas as pd

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_technique_ids(value: Any) -> list[str]:
    """Extract MITRE technique IDs from a string or list."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    if isinstance(value, list):
        text = " ".join(str(v) for v in value)
    else:
        text = str(value)
    return _TECHNIQUE_RE.findall(text)


def _row_chain_id(row: pd.Series, chain_col: str) -> str:
    val = row.get(chain_col, "")
    if pd.isna(val):
        return "unknown"
    return str(val)


def _row_techniques(row: pd.Series) -> list[str]:
    for col in ("Techniques", "chain_techniques", "predicted_chain_techniques"):
        if col in row.index:
            techs = parse_technique_ids(row[col])
            if techs:
                return techs
    return []


def _row_confidence(row: pd.Series) -> float | None:
    for col in ("Confidence Score", "chain_confidence"):
        if col in row.index and pd.notna(row[col]):
            try:
                return float(row[col])
            except (TypeError, ValueError):
                pass
    return None


def _row_explanation(row: pd.Series) -> str:
    for col in ("Explanation", "chain_explanation"):
        if col in row.index and pd.notna(row[col]):
            return str(row[col])
    return ""


def _attack_pattern_object(tech_id: str, created: str) -> dict[str, Any]:
    path = tech_id.replace(".", "/")
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _stix_id("attack-pattern"),
        "created": created,
        "modified": created,
        "name": tech_id,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tech_id,
                "url": f"https://attack.mitre.org/techniques/{path}/",
            }
        ],
    }


def chains_to_stix_bundle(
    summary_df: pd.DataFrame,
    chain_id_col: str | None = None,
) -> dict[str, Any]:
    """
    Build a STIX 2.1 bundle from a filtered chains summary DataFrame.
    One grouping per chain with attack-pattern refs and sequential relationships.
    """
    if summary_df.empty:
        return {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "spec_version": "2.1",
            "objects": [],
        }

    if chain_id_col is None:
        if "Chain ID" in summary_df.columns:
            chain_id_col = "Chain ID"
        elif "chain_id" in summary_df.columns:
            chain_id_col = "chain_id"
        else:
            raise ValueError("summary_df must include Chain ID or chain_id column")

    created = _utc_now()
    objects: list[dict[str, Any]] = []

    for _, row in summary_df.iterrows():
        chain_id = _row_chain_id(row, chain_id_col)
        techs = _row_techniques(row)
        confidence = _row_confidence(row)
        explanation = _row_explanation(row)

        grouping_id = _stix_id("grouping")
        pattern_ids: list[str] = []

        for tech in techs:
            ap = _attack_pattern_object(tech, created)
            objects.append(ap)
            pattern_ids.append(ap["id"])

        for i in range(len(pattern_ids) - 1):
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _stix_id("relationship"),
                    "created": created,
                    "modified": created,
                    "relationship_type": "related-to",
                    "source_ref": pattern_ids[i],
                    "target_ref": pattern_ids[i + 1],
                    "description": f"Technique sequence in chain {chain_id}",
                }
            )

        desc_parts = [f"Chain ID: {chain_id}"]
        if confidence is not None:
            desc_parts.append(f"Confidence: {confidence:.0f}%")
        if explanation:
            desc_parts.append(explanation)

        grouping: dict[str, Any] = {
            "type": "grouping",
            "spec_version": "2.1",
            "id": grouping_id,
            "created": created,
            "modified": created,
            "name": f"Attack chain {chain_id}",
            "description": " | ".join(desc_parts),
            "context": "suspicious-activity",
            "object_refs": list(pattern_ids),
        }
        if confidence is not None:
            grouping["x_chain_confidence"] = confidence
        objects.append(grouping)

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }


def bundle_to_json(bundle: dict[str, Any], indent: int = 2) -> str:
    import json

    return json.dumps(bundle, indent=indent, ensure_ascii=False)
