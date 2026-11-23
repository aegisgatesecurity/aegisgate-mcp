<!-- SPDX-License-Identifier: Apache-2.0 -->
# ML Detection Withdrawn (2026-11-23)

**All neural ML detection in aegisgate-mcp is WITHDRAWN and hard-disabled.**

The CharCNN-BiLSTM model (sha256 `948b6500…`) previously shipped in `models/` was trained on a corpus whose attack-side labels failed audit (~71% flip rate). All detection-rate claims derived from it are void. The model file has been removed from the repository. The ML code path remains for the upcoming retrained model, but cannot be enabled and the loader refuses all models.

**Unaffected:** deterministic MCP tool-call screening, policy checks, and all non-neural functionality.

**Reinstatement:** only after corpus re-audit, scoped rebuild, retrain, and re-baselined metrics. See the platform `docs/ML-WITHDRAWN.md` and internal report `corpus-certification-2026-11-23`.
