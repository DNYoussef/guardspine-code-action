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

from src.analyzer import DiffAnalyzer
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


def test_the_error_type_is_kept_for_the_operator():
    review = _unavailable_review()
    assert review.get("error") == "RuntimeError"


def test_a_provider_failure_is_not_model_prose():
    review = _unavailable_review()
    assert review["concerns"] == []
    assert review["provider"] == "openrouter"


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


def test_a_real_concern_is_still_labelled_as_one():
    """The fix must not launder genuine model findings into 'availability'."""
    findings = _findings_for(["Hardcoded API key in source"])
    messages = [_msg(f) for f in findings]
    assert any(m.startswith("AI concern: Hardcoded API key") for m in messages), messages


def test_a_prefix_in_model_prose_is_still_a_real_concern():
    findings = _findings_for(["AI review incomplete: Hardcoded API key in source"])
    messages = [_msg(f) for f in findings]
    assert any(m.startswith("AI concern: AI review incomplete:") for m in messages), messages


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
