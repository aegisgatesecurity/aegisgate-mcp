> **⚠ WITHDRAWN 2026-11-23 — ML detection is disabled.** The CharCNN-BiLSTM described here was trained on a corpus whose attack-side labels failed audit; all performance claims in this document are void. See docs/ML-WITHDRAWN.md.

<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate MCP — ML Model Card

## Model Details

- **Model name**: AegisGate Threat Detector v15 (shared model)
- **Model type**: Character CNN-BiLSTM with Attention
- **Version**: v15 (char-cnn-bilstm-v15)
- **Release date**: 2026-10-20
- **License**: Apache 2.0
- **Architecture**: 1,596,034 parameters, character-level input (256 chars max),
  Latin-1 vocabulary (256 tokens), ~6.1MB ONNX export (float32)
- **Inference**: <1ms CPU inference via vendored ONNX Runtime (Go + CGO)
- **SHA-256**: `99187453bedb2b8caf21500d2344f2bbe34272c0b3fd4c610c431378dc2f4fe7`
- **Location**: `models/threat_cnn_bilstm.onnx` (removed 2026-11-23 — file no longer shipped)

> **Void 2026-11-23.** Every claim in "Model Details", "Intended Use", "Performance", "Two-Tier Blocking", "Audit Trail", and "Ethical Considerations" below describes the withdrawn model and is retained for historical reference only. The model was withdrawn after its training corpus failed label audit (~71% flip rate); all detection-rate and false-positive claims are void. See [ML-WITHDRAWN.md](ML-WITHDRAWN.md).

> **Note:** This is the same model used by AegisGate Platform and Rampart.
> For full training data, evaluation metrics, and ethical considerations, see
> the [Platform Model Card](../docs/model-card.md).

## Intended Use

- **Primary use**: Detect adversarial AI threats in MCP tool call parameters
  (input scanning) and tool responses (output scanning)
- **Deployment context**: environments where AI agents interact with
  critical infrastructure via MCP protocol
- **Out-of-scope**: Not a general-purpose text classifier. Not a replacement
  for regex pattern matching — it supplements L1/L2 detection as L3.

## Performance

> **VOID 2026-11-23** — all metrics below are void (training corpus label audit failure). Retained for historical reference only; see [ML-WITHDRAWN.md](ML-WITHDRAWN.md).

| Metric | Value |
|--------|-------|
| True Positive Rate (TPR) | 93.48% (test set), 100/100 evasion (full pipeline) |
| False Positive Rate (FPR) | 0.49% (test set), 0.00% (production, full pipeline) |
| F1 Score | 95.78% |
| Evasion Resistance | 100/100 |
| Incremental TPR (L3 over L1+L2) | 97.6% (catches 41 attacks regex misses) |
| Incremental FPR (L3 over L1+L2) | 0.00% (zero additional false positives) |

## Two-Tier Blocking

> **Withdrawn 2026-11-23** — two-tier blocking was removed with neural detection. Retained for historical reference only.

The MCP server used two-tier blocking to prevent false positives:

| Tier | Score Range | Behavior |
|------|-------------|----------|
| Tier 1 | ≥ 0.95 | Block independently |
| Tier 2 | 0.50–0.94 | Block only with L1/L2 corroboration |
| Alert | < 0.50 | Log only, no block |

## Heuristic Fallback (Non-CGO)

When CGO is unavailable or the model fails to load, the server falls back
to heuristic detection:
- Character transposition detection
- Vowel deletion detection
- Word reversal detection
- Leetspeak pattern matching
- NFKC Unicode normalization (homoglyph/ligature defense)
- Encoding and splitting detection

## Audit Trail

> **Historical (withdrawn 2026-11-23).** No `ml_*` audit entries are emitted after the withdrawal; no ML inference occurs.

ML blocks were recorded in the tamper-evident audit log:
- `ml_input_blocked` — input parameter blocked by neural detector
- `ml_response_blocked` — tool response blocked by neural detector
- Entries include threat score, tier, and model version

## Ethical Considerations

- No user data is collected or transmitted — all inference is local
- The model does not generate text — it only classifies threat probability
- Shadow mode allows deployment without blocking for evaluation
- All decisions are auditable via the tamper-evident audit log

---

*Copyright 2024-2026 AegisGate Security, LLC. Licensed under Apache-2.0.*