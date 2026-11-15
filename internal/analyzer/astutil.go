// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"path/filepath"
	"strings"
)

func canonicalType(t astType) string {
	if t.DesugaredQualType != "" {
		return t.DesugaredQualType
	}
	return t.QualType
}

// splitFunctionType separates "int (const char *, size_t)" into return type and
// top-level parameter types. It is intentionally conservative: if the shape is
// ambiguous, parameters are returned empty and the caller treats roles as
// unknown.
func splitFunctionType(qualType string) (string, []string) {
	text := strings.TrimSpace(qualType)
	open := strings.Index(text, " (")
	if open < 0 {
		open = strings.Index(text, "(")
	}
	if open < 0 {
		return text, nil
	}
	returnType := strings.TrimSpace(text[:open])
	parenStart := open
	if text[parenStart] == ' ' {
		parenStart++
	}
	rest := text[parenStart:]
	if !strings.HasPrefix(rest, "(") {
		return returnType, nil
	}
	depth := 0
	end := -1
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return returnType, nil
	}
	paramsText := strings.TrimSpace(rest[1:end])
	if paramsText == "" || paramsText == "void" {
		return returnType, nil
	}
	return returnType, splitTopLevel(paramsText)
}

func splitTopLevel(text string) []string {
	var out []string
	start := 0
	paren, angle, bracket, brace := 0, 0, 0, 0
	for i, r := range text {
		switch r {
		case '(':
			paren++
		case ')':
			paren--
		case '<':
			angle++
		case '>':
			if angle > 0 {
				angle--
			}
		case '[':
			bracket++
		case ']':
			if bracket > 0 {
				bracket--
			}
		case '{':
			brace++
		case '}':
			if brace > 0 {
				brace--
			}
		case ',':
			if paren == 0 && angle == 0 && bracket == 0 && brace == 0 {
				out = append(out, strings.TrimSpace(text[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(text[start:]))
	return out
}

func makeParam(index int, name, typeText string) Param {
	canonical := strings.TrimSpace(typeText)
	param := Param{
		Index:         index,
		Name:          name,
		Type:          canonical,
		CanonicalType: canonical,
		IsPointer:     strings.Contains(canonical, "*"),
		IsVolatile:    strings.Contains(canonical, "volatile"),
	}
	pointee := canonical
	if star := strings.LastIndex(canonical, "*"); star >= 0 {
		pointee = canonical[:star]
	}
	param.IsConst = strings.Contains(pointee, "const")
	base := normalizeTypeBase(pointee)
	param.IsVoidPointer = param.IsPointer && base == "void"
	param.IsInteger = !param.IsPointer && isIntegerBase(base)
	param.IsSigned = param.IsInteger && isSignedBase(base)
	param.Bits = integerBits(base)
	return param
}

func normalizeTypeBase(value string) string {
	replacer := strings.NewReplacer(
		"const", " ",
		"volatile", " ",
		"restrict", " ",
		"__restrict", " ",
		"__restrict__", " ",
		"struct", " ",
		"class", " ",
		"enum", " ",
		"&", " ",
	)
	value = replacer.Replace(value)
	value = strings.ReplaceAll(value, "std::", "")
	return strings.Join(strings.Fields(value), " ")
}

func isIntegerBase(base string) bool {
	switch base {
	case "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
		"int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
		"int64_t", "uint64_t", "int", "unsigned int", "unsigned",
		"long", "unsigned long", "long long", "unsigned long long",
		"short", "unsigned short", "char", "signed char", "unsigned char",
		"unsigned __int128", "__int128":
		return true
	}
	return false
}

func isSignedBase(base string) bool {
	if strings.Contains(base, "unsigned") || strings.HasPrefix(base, "uint") || base == "size_t" || base == "uintptr_t" {
		return false
	}
	return isIntegerBase(base)
}

func integerBits(base string) int {
	switch base {
	case "int8_t", "uint8_t", "char", "signed char", "unsigned char":
		return 8
	case "int16_t", "uint16_t", "short", "unsigned short":
		return 16
	case "int32_t", "uint32_t", "int", "unsigned int", "unsigned":
		return 32
	case "int64_t", "uint64_t", "long", "unsigned long", "long long", "unsigned long long",
		"size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t":
		return 64
	case "__int128", "unsigned __int128":
		return 128
	default:
		return 0
	}
}

// lengthLimitMacro returns the C macro that bounds a logical length parameter.
// The harness must reject oversized inputs rather than silently truncating.
func LengthLimitMacro(param Param) (string, bool) {
	if !param.IsInteger {
		return "", false
	}
	base := normalizeTypeBase(param.CanonicalType)
	switch base {
	case "size_t":
		return "SIZE_MAX", true
	case "ssize_t":
		return "SSIZE_MAX", true
	case "ptrdiff_t", "intptr_t":
		return "INTPTR_MAX", true
	case "uintptr_t":
		return "UINTPTR_MAX", true
	case "uint8_t", "unsigned char":
		return "UINT8_MAX", true
	case "int8_t", "signed char", "char":
		return "INT8_MAX", true
	case "uint16_t", "unsigned short":
		return "UINT16_MAX", true
	case "int16_t", "short":
		return "INT16_MAX", true
	case "uint32_t", "unsigned int", "unsigned":
		return "UINT32_MAX", true
	case "int32_t", "int":
		return "INT32_MAX", true
	case "uint64_t", "unsigned long", "unsigned long long":
		return "UINT64_MAX", true
	case "int64_t", "long", "long long":
		return "INT64_MAX", true
	}
	return "", false
}

// ParseReturnType extracts the return type from a Clang function type string.
func ParseReturnType(signature string) string {
	returnType, _ := splitFunctionType(signature)
	return returnType
}

// ParseFunctionType returns the return type and top-level parameter types.
func ParseFunctionType(signature string) (string, []string) {
	return splitFunctionType(signature)
}

func isHeaderFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".h", ".hh", ".hpp", ".hxx", ".h++", ".inc":
		return true
	default:
		return false
	}
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
