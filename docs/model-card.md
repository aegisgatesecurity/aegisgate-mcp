<!-- SPDX-License-Identifier: Apache-2.0 -->

# AegisGate MCP — ML Model Card

## Model Details

- **Model name**: AegisGate Threat Detector v13 (shared model)
- **Model type**: Character CNN-BiLSTM with Attention
- **Version**: v13 (char-cnn-bilstm-v13)
- **Release date**: 2026-09-23
- **License**: Apache 2.0
- **Architecture**: 1,596,034 parameters, character-level input (256 chars max),
  Latin-1 vocabulary (256 tokens), ~6.2MB ONNX export (float32)
- **Inference**: <1ms CPU inference via vendored ONNX Runtime (Go + CGO)
- **SHA-256**: `329fd89afe153d0b9f01143c50a9a2dd73b1d3613cc87a07b4b83a93172aeaf0`
- **Location**: `models/threat_cnn_bilstm.onnx`

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

| Metric | Value |
|--------|-------|
| True Positive Rate (TPR) | 99.45% (test set), 99.57% (production, 8.5M requests) |
| False Positive Rate (FPR) | 0.85% (test set), 0.00% (production, 8.5M requests) |
| F1 Score | 0.9841 |
| Evasion Resistance | 100/100 |
| Incremental TPR (L3 over L1+L2) | 97.6% (catches 41 attacks regex misses) |
| Incremental FPR (L3 over L1+L2) | 0.00% (zero additional false positives) |

## Two-Tier Blocking

The MCP server uses two-tier blocking to prevent false positives:

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

All ML blocks are recorded in the tamper-evident audit log:
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