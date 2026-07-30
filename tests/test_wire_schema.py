"""The wire schema must drop keywords structured-output backends reject.

Anthropic's structured output 400s on numeric bounds:

    output_config.format.schema: For 'number' type, properties maximum,
    minimum are not supported

It failed identically through Azure, Bedrock and Anthropic direct, so there was
no fallback provider and the reviewer never ran. A run on guardspine-landing
reported "AI models used: 1, failed: 1" against 3 configured and still returned
MERGE.

The bounds themselves are not being relaxed. They stay in the canonical schema
and _parse_ai_review enforces them in Python, fail-closed. The last two tests
here are the ones that matter: they prove the guarantee survived the wire change.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzer import (  # noqa: E402
    AI_REVIEW_PAYLOAD_SCHEMA,
    AI_REVIEW_RESPONSE_SCHEMA,
    UNSUPPORTED_SCHEMA_KEYWORDS,
    DiffAnalyzer,
    wire_schema,
)


def _keys_everywhere(node, found=None):
    """Every mapping key in the tree, including nested property names."""
    if found is None:
        found = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            _keys_everywhere(value, found)
    elif isinstance(node, list):
        for item in node:
            _keys_everywhere(item, found)
    return found


def test_canonical_schema_still_states_the_bounds():
    """Guards the vacuous case. If the bounds were deleted outright rather than
    stripped at the wire, every assertion below would pass for the wrong reason."""
    confidence = AI_REVIEW_PAYLOAD_SCHEMA["properties"]["confidence"]
    assert confidence["minimum"] == 0.0
    assert confidence["maximum"] == 1.0
    scores = AI_REVIEW_PAYLOAD_SCHEMA["properties"]["rubric_scores"]["properties"]
    for key, spec in scores.items():
        assert spec["minimum"] == 1.0, key
        assert spec["maximum"] == 5.0, key


def test_wire_schema_strips_the_rejected_keywords():
    sent = wire_schema(AI_REVIEW_RESPONSE_SCHEMA)
    assert not (_keys_everywhere(sent) & UNSUPPORTED_SCHEMA_KEYWORDS)


def test_wire_schema_keeps_everything_the_model_needs():
    """Stripping must not take the structure with it."""
    sent = wire_schema(AI_REVIEW_RESPONSE_SCHEMA)
    payload = sent["properties"]["codeguard_review"]
    assert payload["type"] == "object"
    assert payload["additionalProperties"] is False
    assert set(payload["required"]) == set(AI_REVIEW_PAYLOAD_SCHEMA["required"])
    assert set(payload["properties"]) == set(AI_REVIEW_PAYLOAD_SCHEMA["properties"])
    # The enums are what actually constrain intent and risk_assessment.
    assert payload["properties"]["intent"]["enum"]
    assert payload["properties"]["risk_assessment"]["enum"]
    scores = payload["properties"]["rubric_scores"]
    assert scores["additionalProperties"] is False
    assert set(scores["required"]) == set(scores["properties"])


def test_rubric_scores_nullability_becomes_anyof():
    """The half of this fix that stripping the bounds would have missed.

    rubric_scores declares "type": ["number", "null"]. A type union is also
    unsupported, so removing the bounds alone would still have 400'd and the
    reviewer would still never have run.
    """
    sent = wire_schema(AI_REVIEW_RESPONSE_SCHEMA)
    scores = sent["properties"]["codeguard_review"]["properties"]["rubric_scores"]
    assert scores["properties"], "no scored fields survived"
    for key, spec in scores["properties"].items():
        assert "type" not in spec, f"{key} still sends a union type"
        assert spec["anyOf"] == [{"type": "number"}, {"type": "null"}], key


def test_no_type_union_survives_anywhere():
    def walk(node):
        if isinstance(node, dict):
            assert not isinstance(node.get("type"), list), node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(wire_schema(AI_REVIEW_RESPONSE_SCHEMA))


def test_single_element_type_list_collapses_to_a_string():
    assert wire_schema({"type": ["string"]}) == {"type": "string"}


def test_union_conversion_keeps_sibling_keys():
    sent = wire_schema({"type": ["number", "null"], "description": "d", "minimum": 1})
    assert sent["description"] == "d"
    assert "minimum" not in sent
    assert sent["anyOf"] == [{"type": "number"}, {"type": "null"}]


def test_wire_schema_does_not_mutate_the_canonical_schema():
    before = repr(AI_REVIEW_RESPONSE_SCHEMA)
    wire_schema(AI_REVIEW_RESPONSE_SCHEMA)
    assert repr(AI_REVIEW_RESPONSE_SCHEMA) == before


def test_wire_schema_spares_a_field_named_like_a_keyword():
    """A field called "minimum" is a name, not a constraint. Filtering property
    maps by keyword would silently delete real fields."""
    schema = {
        "type": "object",
        "properties": {
            "minimum": {"type": "number", "minimum": 0},
            "pattern": {"type": "string", "maxLength": 8},
        },
    }
    sent = wire_schema(schema)
    assert set(sent["properties"]) == {"minimum", "pattern"}
    assert sent["properties"]["minimum"] == {"type": "number"}
    assert sent["properties"]["pattern"] == {"type": "string"}


def test_wire_schema_leaves_non_schema_values_alone():
    assert wire_schema({"required": ["minimum", "maximum"]}) == {
        "required": ["minimum", "maximum"]
    }
    assert wire_schema({"enum": ["a", "b"]}) == {"enum": ["a", "b"]}


def _payload(**overrides):
    body = {
        "schema_version": AI_REVIEW_PAYLOAD_SCHEMA["properties"]["schema_version"]["enum"][0],
        "summary": "s",
        "intent": "test",
        "concerns": [],
        "risk_assessment": "approve",
        "confidence": 0.5,
        "rubric_scores": {
            key: 3 for key in AI_REVIEW_PAYLOAD_SCHEMA["properties"]["rubric_scores"]["properties"]
        },
    }
    body.update(overrides)
    import json

    return json.dumps({"codeguard_review": body})


def test_python_still_rejects_out_of_range_confidence():
    """The bound left the wire, so this is now the ONLY thing enforcing it."""
    analyzer = DiffAnalyzer(ai_review=True)
    for bad in (1.5, -0.1, 7):
        review = analyzer._parse_review_response(_payload(confidence=bad))
        assert review.get("schema_error") is True, bad
        assert review["risk_assessment"] == "request_changes", bad


def test_python_still_rejects_out_of_range_rubric_scores():
    analyzer = DiffAnalyzer(ai_review=True)
    keys = list(AI_REVIEW_PAYLOAD_SCHEMA["properties"]["rubric_scores"]["properties"])
    for bad in (0, 6, -1):
        scores = {key: 3 for key in keys}
        scores[keys[0]] = bad
        review = analyzer._parse_review_response(_payload(rubric_scores=scores))
        assert review.get("schema_error") is True, bad


def test_python_accepts_a_valid_payload():
    """Fail-closed is only meaningful if the open path works."""
    analyzer = DiffAnalyzer(ai_review=True)
    review = analyzer._parse_review_response(_payload())
    assert not review.get("schema_error")
    assert review["risk_assessment"] == "approve"
    assert review["confidence"] == 0.5
