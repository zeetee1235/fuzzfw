// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"encoding/json"
)

// The Clang JSON AST is not a stable public API. These structs intentionally
// capture only the fields fuzzfw consumes, and every consumer treats missing
// fields as unknown rather than guessing.

type astDocument struct {
	ID    string    `json:"id"`
	Kind  string    `json:"kind"`
	Inner []astNode `json:"inner"`
}

type astNode struct {
	ID                  string      `json:"id"`
	Kind                string      `json:"kind"`
	Name                string      `json:"name"`
	MangledName         string      `json:"mangledName"`
	Type                astType     `json:"type"`
	Loc                 astLoc      `json:"loc"`
	Range               astRange    `json:"range"`
	Inner               []astNode   `json:"inner"`
	ReferencedDecl      *astDeclRef `json:"referencedDecl"`
	CastKind            string      `json:"castKind"`
	Opcode              string      `json:"opcode"`
	StorageClass        string      `json:"storageClass"`
	IsImplicit          bool        `json:"isImplicit"`
	IsUsed              bool        `json:"isUsed"`
	Value               string      `json:"value"`
	ValueCategory       string      `json:"valueCategory"`
	ParentDeclContextID string      `json:"parentDeclContextId"`
	PreviousDecl        string      `json:"previousDecl"`
	Variadic            bool        `json:"variadic"`
	Inline              bool        `json:"inline"`
	IsArrow             bool        `json:"isArrow"`
}

type astType struct {
	QualType          string `json:"qualType"`
	DesugaredQualType string `json:"desugaredQualType"`
	TypeAliasDeclID   string `json:"typeAliasDeclId"`
}

type astLoc struct {
	Offset       int     `json:"offset"`
	Line         int     `json:"line"`
	Col          int     `json:"col"`
	TokLen       int     `json:"tokLen"`
	File         string  `json:"file"`
	PresumedFile string  `json:"presumedFile"`
	SpellingLoc  *astLoc `json:"spellingLoc"`
	ExpansionLoc *astLoc `json:"expansionLoc"`
	IncludedFrom *astLoc `json:"includedFrom"`
}

type astRange struct {
	Begin astLoc `json:"begin"`
	End   astLoc `json:"end"`
}

type astDeclRef struct {
	ID           string  `json:"id"`
	Kind         string  `json:"kind"`
	Name         string  `json:"name"`
	MangledName  string  `json:"mangledName"`
	Type         astType `json:"type"`
	StorageClass string  `json:"storageClass"`
}

func (l astLoc) file() string {
	if l.File != "" {
		return l.File
	}
	if l.PresumedFile != "" {
		return l.PresumedFile
	}
	if l.SpellingLoc != nil {
		if file := l.SpellingLoc.file(); file != "" {
			return file
		}
	}
	if l.ExpansionLoc != nil {
		if file := l.ExpansionLoc.file(); file != "" {
			return file
		}
	}
	return ""
}

func (l astLoc) line() int {
	if l.Line > 0 {
		return l.Line
	}
	if l.SpellingLoc != nil && l.SpellingLoc.Line > 0 {
		return l.SpellingLoc.Line
	}
	if l.ExpansionLoc != nil && l.ExpansionLoc.Line > 0 {
		return l.ExpansionLoc.Line
	}
	return 0
}

func (l astLoc) col() int {
	if l.Col > 0 {
		return l.Col
	}
	if l.SpellingLoc != nil && l.SpellingLoc.Col > 0 {
		return l.SpellingLoc.Col
	}
	if l.ExpansionLoc != nil && l.ExpansionLoc.Col > 0 {
		return l.ExpansionLoc.Col
	}
	return 0
}

func (n *astNode) hasKind(kind string) bool {
	if n.Kind == kind {
		return true
	}
	for i := range n.Inner {
		if n.Inner[i].hasKind(kind) {
			return true
		}
	}
	return false
}

func decodeAST(data []byte) (*astDocument, error) {
	var doc astDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
