// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate MCP — Evasion Normalization
// =========================================================================
//
// Provides text normalization functions to counter adversarial evasion
// techniques: Unicode homoglyphs, l33t speak, and character-level spacing.
//
// This package is shared between the regex scanner (mcpsecurity) and the
// ML character normalizer (internal/ml) to ensure both detection layers
// process text through the same evasion-resistant pipeline.
//
// Parity: Unified with Platform, Rampart, and Scanner normalization.
//
// =========================================================================

package evasion

import (
	"strings"
	"unicode"
)

// homoglyphMap maps common visually-confusable Unicode characters (Cyrillic,
// Greek, fullwidth Latin, and other lookalikes) to their Latin ASCII equivalents.
var homoglyphMap = map[rune]rune{
	// Cyrillic → Latin lookalikes
	'а': 'a', 'А': 'a', 'е': 'e', 'Е': 'e', 'о': 'o', 'О': 'o',
	'р': 'p', 'Р': 'p', 'с': 'c', 'С': 'c', 'х': 'x', 'Х': 'x',
	'у': 'y', 'У': 'y', 'і': 'i', 'І': 'i', 'ј': 'j', 'Ј': 'j',
	'ѕ': 's', 'Ѕ': 's', 'қ': 'q',
	'Џ': 'd', 'в': 'b', 'н': 'h', 'Т': 't',
	// Greek → Latin lookalikes
	'α': 'a', 'Α': 'a', 'ε': 'e', 'Ε': 'e', 'ο': 'o', 'Ο': 'o',
	'ν': 'v', 'Ν': 'v', 'ρ': 'p', 'Ρ': 'p', 'τ': 't', 'Τ': 't',
	// Fullwidth Latin (U+FF01–U+FF5E) → ASCII
	'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F',
	'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L',
	'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
	'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X',
	'Ｙ': 'Y', 'Ｚ': 'Z',
	'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
	'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
	'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
	'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
	'ｙ': 'y', 'ｚ': 'z',
	'０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
	'５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
	'　': ' ', '！': '!', '＂': '"', '＃': '#', '＄': '$', '％': '%',
	'＆': '&', '＇': '\'', '（': '(', '）': ')', '＊': '*', '＋': '+',
	'，': ',', '－': '-', '．': '.', '／': '/', '：': ':', '；': ';',
	'＜': '<', '＝': '=', '＞': '>', '？': '?', '＠': '@', '［': '[',
	'＼': '\\', '］': ']', '＾': '^', '＿': '_', '｀': '`', '｛': '{',
	'｜': '|', '｝': '}', '～': '~',
}

// l33tMap maps l33t-speak substitutions back to their letter equivalents.
// Unified across all products (Platform + Rampart + Scanner + MCP).
var l33tMap = map[rune]rune{
	'@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g',
	'9': 'g', '1': 'i', '|': 'i', '!': 'i', '0': 'o', '5': 's',
	'$': 's', '7': 't', '+': 't', '2': 'z',
}

// l33tMapAlt uses alternate mappings where ambiguous (1→l instead of 1→i).
var l33tMapAlt = map[rune]rune{
	'@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g',
	'9': 'g', '1': 'l', '|': 'l', '!': 'i', '0': 'o', '5': 's',
	'$': 's', '7': 't', '+': 't', '2': 'z',
}

// ApplyHomoglyphs replaces visually-confusable Unicode characters with their
// ASCII equivalents. This is idempotent and safe to apply to all text.
func ApplyHomoglyphs(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := homoglyphMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// DeobfuscateL33t reverses common l33t-speak substitutions in word context only.
// A l33t char is only replaced if it has a letter on at least one side,
// preserving standalone numbers (phone numbers, IDs, etc.).
func DeobfuscateL33t(s string) string {
	runes := []rune(s)
	result := make([]rune, len(runes))
	copy(result, runes)

	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			hasLetterBefore := i > 0 && unicode.IsLetter(runes[i-1])
			hasLetterAfter := i < len(runes)-1 && unicode.IsLetter(runes[i+1])
			if hasLetterBefore || hasLetterAfter {
				result[i] = replacement
			}
		}
	}
	return string(result)
}

// NormalizeAggressiveL33t replaces ALL l33t-speak characters with their letter
// equivalents, regardless of context. This is destructive on normal text
// (e.g., "room 4" → "room a"), so it should only be used for generating
// additional variants, not as the primary normalization.
func NormalizeAggressiveL33t(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// NormalizeAggressiveL33tAlt uses the alternate l33t map where 1→l instead of 1→i.
func NormalizeAggressiveL33tAlt(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := l33tMapAlt[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// NormalizeDespaced collapses character-level spacing evasion.
// "I g n o r e   a l l" → "Ignore all"
// Only applies when >40% of alphanumeric characters are single-char-spaced.
func NormalizeDespaced(input string) string {
	if len(input) < 5 {
		return input
	}
	singleCharSpaced := 0
	totalAlphaNum := 0
	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		if isAlphaNum(runes[i]) {
			totalAlphaNum++
			if i+2 < len(runes) && (runes[i+1] == ' ' || runes[i+1] == '\t') && isAlphaNum(runes[i+2]) {
				singleCharSpaced++
			}
		}
	}
	if totalAlphaNum < 4 || singleCharSpaced < totalAlphaNum*2/5 {
		return input
	}
	var result strings.Builder
	var currentWord strings.Builder
	spaceRun := 0
	for _, r := range input {
		if r == ' ' || r == '\t' {
			spaceRun++
			if spaceRun >= 2 {
				if currentWord.Len() > 0 {
					result.WriteString(currentWord.String())
					result.WriteRune(' ')
					currentWord.Reset()
				}
			}
		} else {
			if spaceRun == 1 && currentWord.Len() > 0 {
				// Single space between chars — skip it (this is the evasion)
			}
			spaceRun = 0
			currentWord.WriteRune(r)
		}
	}
	if currentWord.Len() > 0 {
		result.WriteString(currentWord.String())
	}
	despaced := result.String()
	if despaced != input && despaced != "" {
		return despaced
	}
	if totalAlphaNum > 0 && singleCharSpaced > totalAlphaNum/2 {
		var b strings.Builder
		for _, r := range input {
			if r != ' ' && r != '\t' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return input
}

// NormalizeText applies all IDEMPOTENT evasion-resistant normalizations.
// This is safe to apply to all text before regex matching or ML inference:
//  1. Apply homoglyphs (Cyrillic/Greek/fullwidth → ASCII)
//  2. Deobfuscate l33t speak (context-aware, preserves standalone numbers)
//  3. Normalize despaced text (collapse char-level spacing)
//
// Aggressive l33t variants are NOT applied here — they are destructive on
// normal text and should only be used for generating additional variants.
func NormalizeText(input string) string {
	result := input
	result = ApplyHomoglyphs(result)
	result = DeobfuscateL33t(result)
	result = NormalizeDespaced(result)
	return result
}

// NormalizeAllVariants returns the original text plus all normalized variants.
// This allows regex scanners to check multiple normalizations of the same input,
// catching evasions that may not be caught by the idempotent NormalizeText alone.
func NormalizeAllVariants(input string) []string {
	normalized := NormalizeText(input)
	variants := []string{input, normalized}

	// Aggressive l33t variants
	aggressive := NormalizeAggressiveL33t(normalized)
	if aggressive != normalized {
		variants = append(variants, aggressive)
	}

	aggressiveAlt := NormalizeAggressiveL33tAlt(normalized)
	if aggressiveAlt != normalized && aggressiveAlt != aggressive {
		variants = append(variants, aggressiveAlt)
	}

	// Despaced + aggressive l33t
	despaced := NormalizeDespaced(normalized)
	if despaced != normalized {
		variants = append(variants, despaced)
		aggressiveDespaced := NormalizeAggressiveL33t(despaced)
		if aggressiveDespaced != despaced && aggressiveDespaced != aggressive {
			variants = append(variants, aggressiveDespaced)
		}
	}

	return variants
}

func isAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
