// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
)

// BuildDictionary extracts a small, deterministic byte dictionary from
// constants observed in the target and comparison facts. It is evidence, not
// a protocol grammar.
func BuildDictionary(fn *analyzer.Function, fact *analyzer.IRFunctionFact) []string {
	values := append([]string(nil), fn.Constants...)
	values = append(values, fn.CaseConstants...)
	values = append(values, fn.CaseNames...)
	if fact != nil {
		for _, arg := range fact.Arguments {
			for _, use := range arg.ObservedUse {
				if strings.HasPrefix(use, "compare_constant:") {
					values = append(values, strings.TrimPrefix(use, "compare_constant:"))
				}
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		token := dictionaryToken(value)
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
		if len(out) >= 128 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func dictionaryToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if number, err := strconv.ParseInt(value, 10, 64); err == nil {
		if number >= 0 && number <= 255 {
			return fmt.Sprintf("\"\\x%02x\"", number)
		}
		if number >= 0 && number <= 0xffff {
			return fmt.Sprintf("\"\\x%02x\\x%02x\"", number&0xff, (number>>8)&0xff)
		}
		if number >= 0 && number <= 0xffffffff {
			return fmt.Sprintf("\"\\x%02x\\x%02x\\x%02x\\x%02x\"",
				number&0xff, (number>>8)&0xff, (number>>16)&0xff, (number>>24)&0xff)
		}
		return ""
	}
	if len(value) > 64 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "\\x%02x", byte(r))
		}
	}
	b.WriteByte('"')
	return b.String()
}

// BuildCommandConstants extracts discriminator constants from switch cases and
// IR comparison uses. The result is a heuristic token list, not a grammar.
func BuildCommandConstants(fn *analyzer.Function, fact *analyzer.IRFunctionFact, excludedArgs ...int) []string {
	values := append([]string(nil), fn.CaseConstants...)
	excluded := map[int]bool{}
	for _, index := range excludedArgs {
		if index >= 0 {
			excluded[index] = true
		}
	}
	if fact != nil {
		for _, arg := range fact.Arguments {
			if excluded[arg.Index] {
				continue
			}
			for _, use := range arg.ObservedUse {
				if strings.HasPrefix(use, "compare_constant:") {
					values = append(values, strings.TrimPrefix(use, "compare_constant:"))
				}
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		token := dictionaryToken(value)
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
		if len(out) >= 64 {
			break
		}
	}
	sort.Strings(out)
	return out
}

// DictionaryTokenBytes decodes a token produced by dictionaryToken back into
// the byte sequence it represents.
func DictionaryTokenBytes(token string) []byte {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return nil
	}
	body := token[1 : len(token)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			out = append(out, body[i])
			continue
		}
		i++
		if i >= len(body) {
			return nil
		}
		switch body[i] {
		case '\\', '"':
			out = append(out, body[i])
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'x':
			if i+2 >= len(body) {
				return nil
			}
			value, err := strconv.ParseUint(body[i+1:i+3], 16, 8)
			if err != nil {
				return nil
			}
			out = append(out, byte(value))
			i += 2
		default:
			out = append(out, body[i])
		}
	}
	return out
}
