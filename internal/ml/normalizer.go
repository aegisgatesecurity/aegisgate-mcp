// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Character-Level Normalizer
// =========================================================================
//
// Preprocesses raw text into character-level input tensors for the
// Char CNN-BiLSTM model. Converts text to a fixed-length integer array
// suitable for ONNX inference.
//
// Input pipeline:
//   raw text → normalize → truncate/pad → char IDs → [1, max_len] int32 tensor
//
// Character vocabulary: 256 Latin-1 characters (0-255).
// Covers ASCII (0-127) + Latin-1 supplement (128-255) for Western European
// languages (French, German, Spanish, Italian, Portuguese, Scandinavian).
// Unknown characters (beyond Latin-1) are mapped to a special UNK token (id=1).
// Padding is done with a PAD token (id=0).
//
// =========================================================================

package ml

import (
	"strings"
	"unicode"

	"github.com/aegisgatesecurity/aegisgate-mcp/internal/evasion"
	"github.com/aegisgatesecurity/aegisgate-mcp/internal/textnorm/norm"
)

const (
	// MaxSeqLen is the maximum sequence length for the model input.
	MaxSeqLen = 512

	// PadID is the padding token ID.
	PadID = 0

	// UnkID is the unknown character token ID.
	UnkID = 1

	// VocabSize is the size of the character vocabulary.
	VocabSize = 256
)

// CharNormalizer preprocesses text into character-level input for the model.
type CharNormalizer struct {
	maxLen int
}

// NewCharNormalizer creates a new character normalizer with default settings.
func NewCharNormalizer() *CharNormalizer {
	return &CharNormalizer{
		maxLen: MaxSeqLen,
	}
}

// MapRegionalIndicators converts Unicode regional indicator symbols
// (U+1F1E6–U+1F1FF, used in flag emoji spelling attacks) to their
// ASCII letter equivalents (A–Z). This prevents attackers from
// encoding injection payloads using flag emoji that would otherwise
// collapse to UNK tokens.
func MapRegionalIndicators(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			b.WriteRune('A' + (r - 0x1F1E6))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Normalize preprocesses text for model input.
// Steps:
//  1. NFKC normalization (Unicode canonical decomposition + composition)
//     — this maps homoglyphs and compatibility characters to their
//     canonical forms, so "ⅴ" (U+2174) → "v" (U+0076) and "ﬁ" (U+FB01)
//     → "fi". Without this, adversarial inputs using Unicode tricks
//     bypass the model's detection.
//  2. Map regional indicator symbols (flag emoji letters) to ASCII A-Z
//  3. Apply evasion normalization (homoglyphs, context-aware l33t, despaced)
//     — catches fullwidth Unicode, l33t speak, and char-level spacing that
//     NFKC alone doesn't handle. Unified with Platform/Rampart/Scanner.
//  4. Convert to lowercase
//  5. Strip leading/trailing whitespace
//  6. Collapse multiple whitespace
//  7. Truncate to max length
func (cn *CharNormalizer) Normalize(text string) string {
	// NFKC normalization — canonical decomposition + composition.
	// This maps compatibility characters and homoglyphs to their
	// canonical ASCII equivalents where possible.
	text = norm.NFKC.String(text)

	// Map flag emoji regional indicators to ASCII letters
	text = MapRegionalIndicators(text)

	// Evasion normalization — homoglyphs, l33t speak, despaced text.
	// Applied after NFKC to catch what NFKC doesn't (fullwidth Latin,
	// l33t substitutions, character-level spacing).
	text = evasion.NormalizeText(text)

	// Lowercase
	text = strings.ToLower(text)

	// Strip leading/trailing whitespace
	text = strings.TrimSpace(text)

	// Collapse multiple whitespace
	var b strings.Builder
	prevSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	text = b.String()

	// Truncate
	runes := []rune(text)
	if len(runes) > cn.maxLen {
		runes = runes[:cn.maxLen]
	}

	return string(runes)
}

// NormalizeFull preprocesses text identically to Normalize but WITHOUT truncation.
// Used by the sliding-window inference path to get the full normalized text so
// that overlapping 256-char windows can be extracted from it.
func (cn *CharNormalizer) NormalizeFull(text string) string {
	text = norm.NFKC.String(text)
	text = MapRegionalIndicators(text)
	text = evasion.NormalizeText(text)
	text = strings.ToLower(text)
	text = strings.TrimSpace(text)

	var b strings.Builder
	prevSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}

	return b.String()
}

// EncodeRaw maps already-normalized text directly to character IDs without
// re-normalizing. Used by the sliding-window path where the text has already
// been normalized via NormalizeFull and only a substring (window) is being
// encoded. Result is padded to maxLen with PAD_ID.
func (cn *CharNormalizer) EncodeRaw(text string) []int32 {
	runes := []rune(text)

	result := make([]int32, cn.maxLen)
	for i := range result {
		result[i] = PadID
	}

	for i, r := range runes {
		if i >= cn.maxLen {
			break
		}

		if r >= 32 && r <= 126 {
			result[i] = int32(r)
		} else if r >= 128 && r <= 255 {
			result[i] = int32(r)
		} else if r < 128 {
			result[i] = UnkID
		} else {
			result[i] = UnkID
		}
	}

	return result
}

// Encode converts normalized text to a fixed-length integer array for model input.
// Characters are mapped to their code point if in range [32, 126] (printable ASCII)
// or [128, 255] (Latin-1 supplement), otherwise to UNK_ID.
// Result is padded to maxLen with PAD_ID.
func (cn *CharNormalizer) Encode(text string) []int32 {
	normalized := cn.Normalize(text)
	return cn.EncodeRaw(normalized)
}

// EncodeBatch encodes multiple texts into a batch tensor [batch_size, max_len].
func (cn *CharNormalizer) EncodeBatch(texts []string) [][]int32 {
	batch := make([][]int32, len(texts))
	for i, text := range texts {
		batch[i] = cn.Encode(text)
	}
	return batch
}

// Decode reverses the encoding (for debugging/verification only).
// Not used in production inference.
func (cn *CharNormalizer) Decode(ids []int32) string {
	var b strings.Builder
	for _, id := range ids {
		if id == PadID {
			continue // Skip padding
		}
		if id == UnkID {
			b.WriteRune('�') // Replacement character
			continue
		}
		if id >= 32 && id <= 126 {
			b.WriteRune(rune(id)) // Printable ASCII
		} else if id >= 128 && id <= 255 {
			b.WriteRune(rune(id)) // Latin-1 supplement
		}
	}
	return b.String()
}
