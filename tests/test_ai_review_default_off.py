"""AI review sends diff content to model providers, so it must be opt-in.

Both places that set the default have to agree: the action input default in
action.yml, and the fallback entrypoint.py uses when the input is absent.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_action_input_defaults_to_off():
    spec = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert spec["inputs"]["ai_review"]["default"] == "false"


def test_entrypoint_fallback_defaults_to_off():
    src = (ROOT / "entrypoint.py").read_text(encoding="utf-8")
    m = re.search(r'get_env\("INPUT_AI_REVIEW",\s*"(\w+)"\)', src)
    assert m, "entrypoint no longer reads INPUT_AI_REVIEW with a fallback"
    assert m.group(1) == "false"


# A non-L0 change: "billing" in the path sends it to a tier that wants review.
_BILLING_DIFF = (
    "diff --git a/src/billing/charge.py b/src/billing/charge.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/billing/charge.py\n"
    "+++ b/src/billing/charge.py\n"
    "@@ -1,2 +1,2 @@\n"
    "-def charge(amount):\n"
    "-    return amount\n"
    "+def charge(amount):\n"
    "+    return round(amount, 2)\n"
)


def test_disabled_review_says_disabled_not_missing_provider():
    from src.analyzer import AI_REVIEW_DISABLED_REASON, DiffAnalyzer

    result = DiffAnalyzer(openrouter_key="configured", ai_review=False).analyze(_BILLING_DIFF)
    mmr = result.multi_model_review
    assert mmr["tier"] != "L0"
    assert mmr["models_used"] == 0
    assert mmr["reason"] == AI_REVIEW_DISABLED_REASON


def test_enabled_without_providers_still_says_no_providers():
    from src.analyzer import DiffAnalyzer

    result = DiffAnalyzer(ai_review=True).analyze(_BILLING_DIFF)
    assert result.multi_model_review["reason"] == "No AI providers configured"
