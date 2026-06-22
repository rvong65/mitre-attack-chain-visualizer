"""Tests for STIX 2.1 chain export."""
import json

import pandas as pd
import pytest

from src.stix_export import bundle_to_json, chains_to_stix_bundle, parse_technique_ids


def test_parse_technique_ids():
    assert parse_technique_ids("T1059.001, T1003.001") == ["T1059.001", "T1003.001"]
    assert parse_technique_ids("") == []
    assert parse_technique_ids(None) == []


def test_chains_to_stix_bundle_shape():
    summary = pd.DataFrame(
        [
            {
                "Chain ID": 1,
                "Techniques": "T1059.001, T1547.001",
                "Confidence Score": 75.0,
                "Explanation": "PowerShell then persistence.",
            }
        ]
    )
    bundle = chains_to_stix_bundle(summary)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) >= 3  # 2 patterns + 1 rel + 1 grouping

    types = {o["type"] for o in bundle["objects"]}
    assert "attack-pattern" in types
    assert "grouping" in types
    assert "relationship" in types

    for ap in [o for o in bundle["objects"] if o["type"] == "attack-pattern"]:
        ext_id = ap["external_references"][0]["external_id"]
        assert ext_id.startswith("T")


def test_bundle_to_json_roundtrip():
    summary = pd.DataFrame([{"chain_id": 0, "chain_techniques": "T1003.001", "chain_confidence": 50}])
    raw = bundle_to_json(chains_to_stix_bundle(summary))
    parsed = json.loads(raw)
    assert parsed["type"] == "bundle"


def test_empty_summary():
    bundle = chains_to_stix_bundle(pd.DataFrame())
    assert bundle["objects"] == []


def test_missing_chain_id_column_raises():
    with pytest.raises(ValueError, match="Chain ID"):
        chains_to_stix_bundle(pd.DataFrame([{"foo": 1}]))
