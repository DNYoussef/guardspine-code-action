"""Gate: a provider outage is not a finding about the customer's code.

Observed on a real PR (guardspine-sales-playbook-demo#8). One provider 400'd
and this reached the customer's pull request as a HIGH item under "Reviewer
Action Required":

    AI concern: AI review failed: Error code: 400 - {'error': {'message':
    'Provider returned error', ..., 'raw': '{"type":"error","error":{...
    "message":"Your credit balance is too low to access the Anthropic API..."
    ..., 'user_id': 'user_2mc3uwnrLmhuDbozLov5njnmjfS'}

Two separate defects in one line.

DISCLOSURE. The raw provider exception is interpolated into a concern, and
concerns are rendered into a PR comment on a customer repository. That publishes
our internal user id, provider routing, request ids, and our billing state to
whoever can read the PR. The parse/schema failure paths in the same function
already avoid this -- they emit a fixed sentence and keep the detail in
`raw_response` -- so the convention existed and the provider paths missed it.

CATEGORY. "AI concern:" means the reviewers found something wrong with the
change. An unreachable provider is not a property of the diff. Presenting it as
one teaches reviewers that these findings are noise, which is the precise
failure mode a governance product cannot afford.

What must NOT change: the review still fails closed. Less assurance should mean
more human review, and the tier is driven by risk_assessment, not by whether a
finding was emitted.
"""

import pytest

from src.analyzer import AI_UNAVAILABLE_PREFIX, DiffAnalyzer
from src.risk_classifier import RiskClassifier

# A realistic provider error: nested JSON, billing state, an internal user id.
PROVIDER_ERROR = (
    "Error code: 400 - {'error': {'message': 'Provider returned error', "
    "'code': 400, 'metadata': {'raw': '{\"message\":\"Your credit balance is "
    "too low to access the Anthropic API\"}', 'provider_name': 'Azure'}}, "
    "'user_id': 'user_2mc3uwnrLmhuDbozLov5njnmjfS'}"
)

SECRETS = ("user_2mc3uwnrLmhuDbozLov5njnmjfS", "credit balance", "Azure", "user_id")


def _unavailable_review() -> dict:
    """Drive the REAL path: a provider that raises.

    Calling _fail_closed_review directly would prove nothing -- the leak was
    never in that function, it was in the reason its callers handed it.
    """
    analyzer = DiffAnalyzer.__new__(DiffAnalyzer)

    def _boom(provider, model, prompt):
        raise RuntimeError(PROVIDER_ERROR)

    analyzer._call_provider = _boom
    analyzer._rubric_packs = None
    return DiffAnalyzer._get_model_review(
        analyzer, "openrouter", "claude-sonnet-4", "diff", [], "default", True,
    )


# ---------------------------------------------------------------------------
# Disclosure
# ---------------------------------------------------------------------------

def test_the_provider_error_never_reaches_a_concern():
    review = _unavailable_review()
    rendered = " ".join(review["concerns"]) + " " + review["summary"]
    for secret in SECRETS:
        assert secret not in rendered, (
            f"{secret!r} would be published to the customer's pull request"
        )


def test_the_detail_is_still_kept_for_the_operator():
    """Suppressing it from the PR comment must not mean losing it. The
    operator needs the real error; it belongs in the diagnostic channel."""
    review = _unavailable_review()
    assert PROVIDER_ERROR in review.get("error", "")


def test_the_concern_says_which_provider_failed_without_the_payload():
    review = _unavailable_review()
    concern = review["concerns"][0]
    assert concern.startswith(AI_UNAVAILABLE_PREFIX)
    assert "openrouter" in concern


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------

def _findings_for(concerns: list[str]) -> list:
    classifier = RiskClassifier(rubric="default")
    analysis = {
        "files_changed": 1, "lines_added": 1, "lines_removed": 0,
        "files": [{"path": "src/app.py", "additions": 1, "deletions": 0, "hunks": []}],
        "sensitive_zones": [],
        "consensus_risk": "request_changes",
        "agreement_score": 1.0,
        "multi_model_review": {"consensus": {"combined_concerns": concerns}},
    }
    return classifier.classify(analysis)["findings"]


def _msg(finding) -> str:
    return finding["message"] if isinstance(finding, dict) else finding.message


def _fid(finding) -> str:
    return finding["id"] if isinstance(finding, dict) else finding.id


def test_an_outage_is_not_labelled_as_a_concern_about_the_code():
    findings = _findings_for([f"{AI_UNAVAILABLE_PREFIX} openrouter returned an error"])
    outage = [f for f in findings if AI_UNAVAILABLE_PREFIX in _msg(f)]
    assert outage, "the reviewer is told nothing about the incomplete review"
    for finding in outage:
        assert not _msg(finding).startswith("AI concern:"), (
            "an unreachable provider is being presented as a defect in the diff"
        )


def test_a_real_concern_is_still_labelled_as_one():
    """The fix must not launder genuine model findings into 'availability'."""
    findings = _findings_for(["Hardcoded API key in source"])
    messages = [_msg(f) for f in findings]
    assert any(m.startswith("AI concern: Hardcoded API key") for m in messages), messages


def test_the_two_kinds_are_distinguishable_by_id():
    findings = _findings_for([
        f"{AI_UNAVAILABLE_PREFIX} openrouter returned an error",
        "Hardcoded API key in source",
    ])
    ids = {_fid(f) for f in findings if _fid(f).startswith(("AI-CONCERN", "AI-UNAVAILABLE"))}
    assert any(i.startswith("AI-UNAVAILABLE") for i in ids), ids
    assert any(i.startswith("AI-CONCERN") for i in ids), ids


# ---------------------------------------------------------------------------
# What must not change
# ---------------------------------------------------------------------------

def test_the_review_still_fails_closed():
    """Less assurance means more human review. The verdict comes from
    risk_assessment, not from whether a finding was rendered."""
    review = _unavailable_review()
    assert review["risk_assessment"] == "request_changes"
    assert review["confidence"] == 0.0


def test_parse_failures_keep_their_existing_wording():
    """These paths were already correct -- fixed sentence, detail in
    raw_response. This change must not disturb them."""
    analyzer = DiffAnalyzer.__new__(DiffAnalyzer)
    review = DiffAnalyzer._fail_closed_review(
        analyzer,
        "AI review output rejected: top-level value is not an object",
        schema_error=True,
        raw_response='{"junk": true}',
    )
    assert review["concerns"] == [
        "AI review output rejected: top-level value is not an object"
    ]
    assert not review["concerns"][0].startswith(AI_UNAVAILABLE_PREFIX)
