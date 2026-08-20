# Example report

This hypothetical mixed result demonstrates the required Markdown and embedded
JSON structure. Replace every value with evidence from the current PR and
report.

## Liveness primer review

**Conclusion:** Finding changes are only partially consistent with the stated intent
(`mixed_or_partially_explained`)<br>
**Confidence:** medium · **Review priority:** medium

The PR describes removing false positives for framework-registered callbacks.
Eighteen of 21 dropped findings match that intent, while three dropped ordinary
functions are not explained and may represent recall loss.

### Flags

- **Likely precision improvement** (`likely_precision_improvement`, high
  confidence, low priority): 18 dropped `DEAD001` findings are callbacks
  registered through the framework mechanism described in the PR.
- **Possible recall loss** (`possible_recall_loss`, medium confidence, medium
  priority): three dropped findings do not use that registration mechanism and
  remain apparently unreferenced.

### Evidence

- `project-a/src/handlers.py:84` — dropped `DEAD001`: `on_ready` is registered
  in the adjacent handler table, matching the documented false-positive fix.
- `project-b/plugin/hooks.py:41` — dropped `DEAD001`: `after_load` is registered
  through the framework decorator addressed by the PR.
- `project-c/utils/cleanup.py:117` — dropped `DEAD001`:
  `remove_stale_entries` has no visible registration or reference in the
  relevant source, so its disappearance is not explained by the stated fix.

Totals: **0 new, 21 dropped, 0 changed** across three projects and one rule.

### Limitations

Static source inspection cannot establish whether `remove_stale_entries` is
reached dynamically. Three representative examples are shown; aggregate counts
use the complete report rollups.

<details>
<summary>Machine-readable verdict</summary>

```json
{
  "document_kind": "liveness-primer-review",
  "verdict_schema_version": "1.0",
  "source_report": {
    "artifact_name": "liveness-primer-report.json",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "schema_version": "2.2.0",
    "tool": "example-detector",
    "base_sha": "1111111111111111111111111111111111111111",
    "head_sha": "2222222222222222222222222222222222222222",
    "totals": {
      "new": 0,
      "dropped": 21,
      "changed": 0,
      "changed_confidence_only": 0,
      "changed_message_only": 0,
      "changed_severity_only": 0
    }
  },
  "intent": {
    "source": "pr_body",
    "inferred": false,
    "summary": "Remove false positives for framework-registered callbacks without changing detection of ordinary unused functions."
  },
  "conclusion": {
    "id": "mixed_or_partially_explained",
    "label": "Finding changes are only partially consistent with the stated intent",
    "confidence": "medium",
    "review_priority": "medium",
    "summary": "Eighteen dropped findings match the documented correction, while three dropped ordinary functions are not explained.",
    "evidence": [
      "E1",
      "E2",
      "E3"
    ]
  },
  "flags": [
    {
      "id": "likely_precision_improvement",
      "label": "Likely precision improvement",
      "confidence": "high",
      "review_priority": "low",
      "summary": "Eighteen dropped findings are callbacks registered through the mechanism described in the PR.",
      "evidence": [
        "E1",
        "E2"
      ]
    },
    {
      "id": "possible_recall_loss",
      "label": "Possible recall loss",
      "confidence": "medium",
      "review_priority": "medium",
      "summary": "Three dropped findings do not appear to use the registration mechanism addressed by the PR.",
      "evidence": [
        "E3"
      ]
    }
  ],
  "evidence": [
    {
      "id": "E1",
      "project": "project-a",
      "diff_class": "dropped",
      "rule_or_kind": "DEAD001",
      "path": "src/handlers.py",
      "line": 84,
      "summary": "The callback is registered in the adjacent handler table.",
      "supports": [
        "mixed_or_partially_explained",
        "likely_precision_improvement"
      ]
    },
    {
      "id": "E2",
      "project": "project-b",
      "diff_class": "dropped",
      "rule_or_kind": "DEAD001",
      "path": "plugin/hooks.py",
      "line": 41,
      "summary": "The callback uses the framework decorator addressed by the PR.",
      "supports": [
        "mixed_or_partially_explained",
        "likely_precision_improvement"
      ]
    },
    {
      "id": "E3",
      "project": "project-c",
      "diff_class": "dropped",
      "rule_or_kind": "DEAD001",
      "path": "utils/cleanup.py",
      "line": 117,
      "summary": "No relevant registration or reference was visible in the inspected source.",
      "supports": [
        "mixed_or_partially_explained",
        "possible_recall_loss"
      ]
    }
  ],
  "limitations": [
    "Static source inspection cannot establish whether remove_stale_entries is reached dynamically."
  ],
  "sampling": {
    "max_examples_per_verdict": 3,
    "representative_examples_shown": 3,
    "used_complete_rollups": true,
    "individual_diffs_sampled": false
  }
}
```

</details>
