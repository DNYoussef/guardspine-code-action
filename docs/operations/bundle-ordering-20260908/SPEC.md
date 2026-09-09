# Producer draft sanitization contract

Base: 3b9574e04fa1dbf3b6d4d2729a10f50bf36f4545. Unaccepted candidate only.

All proofs/signatures are produced after sanitization and validation. Keep the
public no-callback output contract and envelope-only seal_bundle behavior.
No external artifact rehasher, new dependencies, higher limits or pin upgrades.

The producer creates a detached JSON-native draft only on the callback path.
Keep constructor-only protocol fields private by exact origin/position, not by
matching keys in arbitrary user subtrees: version/spec/created_at, event types,
generated timestamps and analysis/risk system actors. PR timestamps/actors and
approval actors remain scanned. Same-value user strings are not exempt.
Keep only format-valid digests at explicit provenance slots private; no recursive
hash-name exemptions on this path. Preserve the metadata provider's known fixed
enum and its derived nonnegative signal_count. User numeric content remains scanned.
User keys in free-form content are additionally presented as string values because
the real engine otherwise leaves JSON keys unscanned. A changed key is refused,
not renamed or restored. No blanket exemption for benign-looking dynamic keys.
Key classification is separate from value protection: fixed analyzer schema names
at their exact review/consensus/coverage/score-map positions need not be presented
as customer text. Existing exact protected dictionary-member paths also identify
fixed schema names. Always traverse their values. Unknown siblings, descendants,
skipped-pack keys and signer IDs remain scanned; classify each occurrence before
deduplication. List-element schema applies only to actual integer list positions,
never arbitrary dictionary keys that resemble indices. No whole-subtree exemption.

Compare exact recursive shape/types and non-string values (including signed zero)
before producing any proof. The finite protected string inventory is:

- Bundle ID; context repository/commit; PR timestamp/head SHA; approval commit/tier;
  summary risk tier/decision; snapshot preliminary tier; optional signer key ID.
- Governance catalogue version, rubric_input and requested/loaded pack entries;
  skipped-pack keys are protected through key scanning.
- Finding id/rule_id/source_pack/severity/zone/control_category; risk-driver
  type/zone/rule/severity/tier at their explicit record positions.
- Review model_name/model_id/provider, risk_assessment and intent; snapshot
  ai_summary.intent, multi_model_review.rubric_name and consensus.consensus_risk.
- Explicit provenance digest slots; all strings in the three sanitization
  projections except salt_fingerprint; the key/signing-label inventory.

These fields remain scanned/equal unless specifically withheld below or above.
Configured rubric selectors can be paths and must refuse if changed; this records
the selector, not custom policy content bytes, replayability or trusted invocation.
Messages, descriptions, rationale, file/location strings, control display names,
skipped reasons and driver matched_patterns remain redactable explanatory text.
No recursive field-name policy applies to arbitrary user dictionaries.

Public catalogue boundary: freeze the installed RiskClassifier.shipped_rubrics()
catalogue per operation, never repository-aware discovery. Withhold only string
members at governance requested_packs/loaded_packs indices and finding source_pack.
List positions use None placeholders and must survive validation before restoration.
For findings with a public source_pack, reuse the existing shipped-file parser to
get that pack's public rule IDs. Withhold only a matching rule_id and the exact
classifier-generated RUBRIC-<rule_id> finding ID. Unknown/private IDs remain
scanned/equal. Identical text in user messages or keys is not exempt. Catalogue
lookup/parser failure refuses with a fixed error. This preserves public enum
values that the pinned engine otherwise changes; no changed scan result is restored.
Duplicate keys on the strict draft JSON path are refused before json parsing can
discard them. Private signing material never enters the engine.
The legacy default JSON/SARIF path still collapses duplicate keys; this leaf
preserves compatibility, not an endorsement or acceptance of that separate gap.
Malformed review containers are refused with a fixed producer-draft error.
The configured salt fingerprint remains scanned content, not a format-guaranteed
digest exemption. If redacted, that redaction remains in each signed projection;
post-scan accounting cannot restore it or edit fields outside the four accounting
fields. Category names are trusted outcome metadata, not scanned customer text:
the pinned production adapter always emits an empty redactions_by_type. A future
decoder adding category names needs a bounded category contract and its own gate;
a character-class regex would not prove that an arbitrary label contains no PII.

Only after validation may outcome-only accounting refresh applied_to/counts/status
in current envelope projections. Preserve sanitized strings and historical event
snapshots; later SARIF is not retroactively included. Accounting errors refuse.
Engine/adapter generic failures retain existing fail-open policy only through
original-only fallback plus error accounting, no credited scan. PIIShieldError and
returned invalid structure/identity always stop with fixed privacy-safe reporting.
Entrypoint draft rejections distinguish producer_input, accounting,
structure_identity and unknown invalid_draft using fixed labels, never error text.

Acceptance: fail-first event-chain regression; real pinned engine positive PII
controls, whole-artifact absence with planted leak control; numeric/shape/identity
and accounting mutation rejection before hashes/signatures; input isolation,
no-callback types, unchanged/copied result, original-only fallback; actual installed
kernel item proofs and separate trusted-signature/event verifier with tamper controls;
actual configured packs plus a fired shipped rule with unchanged attribution;
existing reporting/producer regressions and named historical consent xfail recorded
separately, never counted as passing. Exact Git-byte pins and full-tree immutable
snapshot, non-author Opus HIGH/Gemini HIGH inspections and independently confined
Linux execution are required before acceptance. No claim of A2/A-B completion.

Schema compatibility acceptance additionally uses actual normal, deliberation,
failed and disabled analyzer packing, the source-derived intent/risk enum matrix,
real PII-value controls, same-name keys in unknown nested dictionaries, private
key names, and schema deletion/rename refusals before proofs. Known schema names
must not create exemptions for arbitrary user values or arbitrary user keys.

R7 closes R6 review findings F1/F2; R6 is not accepted. Keep its frozen reviews.
Use one complete fixed-key inventory at exact analyzer dictionary paths, with
only actual list indices normalized to the int sentinel. At mapped nodes this
inventory alone governs key exclusion; protected identity values remain separate.
Derive exact path domains and key unions from real successful, failed,
deliberation, no-provider and AI-disabled producers, including provider metadata
and post-raw_response removal. Directly assert callback labels exclude schema
keys and include the same names at unknown positions. Added/removed key and
path controls must falsify the drift oracle. No global name exemptions.
R7 is one corrective build and inspection round following the recorded RCA;
unresolved material findings require the standing architectural escalation.
