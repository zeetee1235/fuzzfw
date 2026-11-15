// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

type globalInfo struct {
	Name    string
	Type    string
	Const   bool
	Storage string
}

type astIndex struct {
	root          string
	directory     string
	contexts      map[string]string
	globalIDs     map[string]globalInfo
	packedRecords map[string]bool
}

func newASTIndex(root, directory string) *astIndex {
	return &astIndex{
		root:          root,
		directory:     directory,
		contexts:      map[string]string{},
		globalIDs:     map[string]globalInfo{},
		packedRecords: map[string]bool{},
	}
}

func (idx *astIndex) build(doc *astDocument, variantFile string) {
	idx.indexContexts(doc.Inner, "", variantFile)
	idx.indexGlobals(doc.Inner, false)
}

func (idx *astIndex) indexContexts(nodes []astNode, parent, lastFile string) string {
	for i := range nodes {
		node := &nodes[i]
		if file := idx.resolveFile(node.Loc.file()); file != "" {
			lastFile = file
		}
		qualified := parent
		if isContextKind(node.Kind) && node.Name != "" {
			qualified = joinQualified(parent, node.Name)
			idx.contexts[node.ID] = qualified
			if node.hasKind("PackedAttr") {
				idx.packedRecords[qualified] = true
			}
		}
		if len(node.Inner) > 0 {
			childParent := parent
			if qualified != parent {
				childParent = qualified
			}
			lastFile = idx.indexContexts(node.Inner, childParent, lastFile)
		}
	}
	return lastFile
}

func (idx *astIndex) indexGlobals(nodes []astNode, insideFunction bool) {
	for i := range nodes {
		node := &nodes[i]
		if !insideFunction && node.Kind == "VarDecl" && node.ID != "" {
			idx.globalIDs[node.ID] = globalInfo{
				Name:    node.Name,
				Type:    node.Type.QualType,
				Const:   strings.Contains(node.Type.QualType, "const"),
				Storage: node.StorageClass,
			}
		}
		childInside := insideFunction || isFunctionKind(node.Kind)
		idx.indexGlobals(node.Inner, childInside)
	}
}

func (idx *astIndex) collect(doc *astDocument, variant Variant, cfg *config.Config) ([]Function, []Declaration) {
	var functions []Function
	var declarations []Declaration
	seenFunctions := map[string]bool{}
	seenDeclarations := map[string]bool{}
	initialFile := variant.File
	if !filepath.IsAbs(initialFile) {
		initialFile = filepath.Join(idx.root, initialFile)
	}
	idx.collectNodes(doc.Inner, "", initialFile, variant, cfg, &functions, &declarations, seenFunctions, seenDeclarations)
	sort.Slice(functions, func(i, j int) bool {
		if functions[i].Source != functions[j].Source {
			return functions[i].Source < functions[j].Source
		}
		if functions[i].Line != functions[j].Line {
			return functions[i].Line < functions[j].Line
		}
		return functions[i].ID < functions[j].ID
	})
	sort.Slice(declarations, func(i, j int) bool {
		if declarations[i].Source != declarations[j].Source {
			return declarations[i].Source < declarations[j].Source
		}
		return declarations[i].QualifiedName < declarations[j].QualifiedName
	})
	return functions, declarations
}

func (idx *astIndex) collectNodes(
	nodes []astNode,
	parentCtx string,
	lastFile string,
	variant Variant,
	cfg *config.Config,
	functions *[]Function,
	declarations *[]Declaration,
	seenFunctions map[string]bool,
	seenDeclarations map[string]bool,
) string {
	for i := range nodes {
		node := &nodes[i]
		if file := idx.resolveFile(node.Loc.file()); file != "" {
			lastFile = file
		}
		if node.IsImplicit {
			continue
		}
		if isFunctionKind(node.Kind) {
			source := lastFile
			if source == "" {
				source = idx.resolveFile(node.Loc.file())
			}
			if source == "" || !fsutil.Within(idx.root, source) {
				continue
			}
			qualified := idx.qualifiedName(node, parentCtx)
			definition := node.hasKind("CompoundStmt") || node.hasKind("CXXTryStmt")
			if definition {
				fn := idx.buildFunction(node, qualified, source, variant, cfg)
				key := fn.MangledName + "\x00" + fn.Signature + "\x00" + fn.Source
				if seenFunctions[key] {
					continue
				}
				seenFunctions[key] = true
				*functions = append(*functions, fn)
			} else {
				declarationReturn, _ := splitFunctionType(node.Type.QualType)
				declaration := Declaration{
					Name:          node.Name,
					QualifiedName: qualified,
					MangledName:   node.MangledName,
					Signature:     node.Type.QualType,
					ReturnType:    declarationReturn,
					Source:        source,
					Line:          node.Loc.line(),
					Language:      variant.Language,
					VariantID:     variant.ID,
					IsStatic:      node.StorageClass == "static",
				}
				key := declaration.Name + "\x00" + declaration.Signature + "\x00" + declaration.Source
				if !seenDeclarations[key] {
					seenDeclarations[key] = true
					*declarations = append(*declarations, declaration)
				}
			}
			// Do not descend into function bodies: lambdas and local classes are
			// not P0 fuzz targets and would confuse symbol mapping.
			continue
		}
		if len(node.Inner) == 0 {
			continue
		}
		childParent := parentCtx
		if isContextKind(node.Kind) && node.Name != "" {
			childParent = joinQualified(parentCtx, node.Name)
			if mapped := idx.contexts[node.ID]; mapped != "" {
				childParent = mapped
			}
		}
		lastFile = idx.collectNodes(node.Inner, childParent, lastFile, variant, cfg, functions, declarations, seenFunctions, seenDeclarations)
	}
	return lastFile
}

func (idx *astIndex) buildFunction(node *astNode, qualified, source string, variant Variant, cfg *config.Config) Function {
	returnType, _ := splitFunctionType(node.Type.QualType)
	fn := Function{
		Language:        variant.Language,
		Name:            node.Name,
		QualifiedName:   qualified,
		MangledName:     node.MangledName,
		Signature:       node.Type.QualType,
		ReturnType:      returnType,
		Source:          fsutil.Rel(idx.root, source),
		Line:            node.Loc.line(),
		Column:          node.Loc.col(),
		VariantID:       variant.ID,
		TranslationUnit: variant.File,
		Definition:      true,
		IsMethod:        isMethodKind(node.Kind),
		Variadic:        strings.Contains(node.Type.QualType, "..."),
	}
	if fn.MangledName == "" {
		fn.MangledName = fn.Name
	}
	if isHeaderFile(source) {
		fn.Header = fsutil.Rel(idx.root, source)
	}
	if node.StorageClass == "static" {
		if fn.IsMethod {
			fn.IsStaticMethod = true
		} else {
			fn.InternalLinkage = true
		}
	}
	if fn.IsMethod {
		if idx := strings.LastIndex(qualified, "::"); idx > 0 {
			fn.ParentType = qualified[:idx]
		}
	}
	for _, child := range node.Inner {
		if child.Kind != "ParmVarDecl" {
			continue
		}
		param := makeParam(len(fn.Params), child.Name, child.Type.QualType)
		if child.Type.DesugaredQualType != "" {
			param.CanonicalType = child.Type.DesugaredQualType
		}
		param.Evidence = append(param.Evidence, fmt.Sprintf("ast_param:%s", child.Type.QualType))
		fn.Params = append(fn.Params, param)
	}
	fn.ID = functionID(fn)
	fn.Evidence = append(fn.Evidence, Evidence{
		Kind:       "ast_definition",
		Source:     fmt.Sprintf("%s:%d", fn.Source, fn.Line),
		Symbol:     fn.MangledName,
		Detail:     fn.Signature,
		Confidence: "observed",
	})
	body := idx.analyzeBody(node, source)
	fn.DirectCallees = body.calls
	fn.IndirectCalls = uniqueStrings(body.indirect)
	fn.GlobalReads = sortedKeys(body.reads)
	fn.GlobalWrites = sortedKeys(body.writes)
	fn.HardwareFlags = sortedKeys(body.flags)
	fn.Constants = uniqueStrings(body.constants)
	fn.Reasons = append(fn.Reasons, body.reasons...)
	fn.Evidence = append(fn.Evidence, body.evidence...)
	return fn
}

func functionID(fn Function) string {
	identity := struct {
		Language      string `json:"language"`
		Variant       string `json:"variant_id"`
		Source        string `json:"source"`
		QualifiedName string `json:"qualified_name"`
		MangledName   string `json:"mangled_name"`
		Signature     string `json:"signature"`
		USR           string `json:"usr,omitempty"`
	}{
		Language:      fn.Language,
		Variant:       fn.VariantID,
		Source:        fn.Source,
		QualifiedName: fn.QualifiedName,
		MangledName:   fn.MangledName,
		Signature:     fn.Signature,
		USR:           fn.USR,
	}
	hash, _ := fsutil.HashJSON(identity)
	return "fn_" + hash[:24]
}

type bodyInfo struct {
	calls     []CallRef
	constants []string
	indirect  []string
	reads     map[string]bool
	writes    map[string]bool
	flags     map[string]bool
	evidence  []Evidence
	reasons   []string
}

func (idx *astIndex) analyzeBody(node *astNode, source string) bodyInfo {
	info := bodyInfo{
		reads:  map[string]bool{},
		writes: map[string]bool{},
		flags:  map[string]bool{},
	}
	seenCalls := map[string]bool{}
	for i := range node.Inner {
		child := &node.Inner[i]
		if child.Kind == "ParmVarDecl" {
			continue
		}
		idx.walkBody(child, source, false, &info, seenCalls)
	}
	return info
}

func (idx *astIndex) walkBody(node *astNode, source string, writeCtx bool, info *bodyInfo, seenCalls map[string]bool) {
	if node.Kind == "IntegerLiteral" || node.Kind == "StringLiteral" || node.Kind == "CharacterLiteral" {
		if value := astValueString(node); value != "" {
			info.constants = append(info.constants, value)
		}
	}
	if node.Kind == "GCCAsmStmt" || node.Kind == "MSAsmStmt" {
		info.flags["ARCH_ASM"] = true
		info.evidence = append(info.evidence, Evidence{
			Kind: "inline_asm", Source: sourceLocation(source, node), Confidence: "observed",
		})
	}
	if node.Kind == "AtomicExpr" {
		info.flags["RTOS_CONTEXT"] = true
		info.reasons = append(info.reasons, "atomic operation observed; concurrency semantics are not modeled")
	}
	if node.Kind == "CStyleCastExpr" || node.Kind == "CXXStaticCastExpr" || node.Kind == "CXXReinterpretCastExpr" {
		if node.CastKind == "IntegralToPointer" || node.CastKind == "IntToPtr" || node.CastKind == "PointerToIntegral" {
			info.flags["MMIO_DIRECT"] = true
			info.evidence = append(info.evidence, Evidence{
				Kind: "integer_pointer_cast", Source: sourceLocation(source, node),
				Detail: node.CastKind, Confidence: "observed",
			})
		}
	}
	if strings.Contains(node.Type.QualType, "volatile") &&
		(node.Kind == "UnaryOperator" || node.Kind == "ArraySubscriptExpr" || node.Kind == "MemberExpr") {
		info.flags["MMIO_DIRECT"] = true
		info.evidence = append(info.evidence, Evidence{
			Kind: "volatile_access", Source: sourceLocation(source, node),
			Detail: "volatile dereference; MMIO is not proven", Confidence: "observed",
		})
	}
	if isCallKind(node.Kind) {
		if call, direct := findDirectCallee(node); direct {
			key := call.Symbol + "\x00" + call.Name + "\x00" + fmt.Sprint(call.Line)
			if !seenCalls[key] {
				seenCalls[key] = true
				call.Source = source
				call.Line = node.Loc.line()
				info.calls = append(info.calls, call)
				for flag, reason := range hardwareFlagsForCall(call.Name) {
					info.flags[flag] = true
					info.reasons = append(info.reasons, reason)
				}
			}
		} else {
			desc := indirectDescription(node)
			if desc == "" {
				desc = "unknown_indirect_call"
			}
			info.indirect = append(info.indirect, desc)
			info.flags["INDIRECT_UNKNOWN"] = true
			info.evidence = append(info.evidence, Evidence{
				Kind: "indirect_call", Source: sourceLocation(source, node),
				Detail: desc, Confidence: "observed",
			})
		}
	}
	if node.Kind == "DeclRefExpr" && node.ReferencedDecl != nil {
		if global, ok := idx.globalIDs[node.ReferencedDecl.ID]; ok {
			info.reads[global.Name] = true
			if writeCtx {
				info.writes[global.Name] = true
				if !global.Const {
					info.flags["INIT_REQUIRED"] = true
				}
			}
			info.evidence = append(info.evidence, Evidence{
				Kind: "global_reference", Source: sourceLocation(source, node),
				Symbol: global.Name, Detail: global.Type, Confidence: "observed",
			})
		}
	}
	for name := range idx.packedRecords {
		if strings.Contains(node.Type.QualType, name) {
			info.flags["ABI_LAYOUT"] = true
			info.evidence = append(info.evidence, Evidence{
				Kind: "packed_type_use", Source: sourceLocation(source, node),
				Detail: name, Confidence: "observed",
			})
		}
	}
	for i := range node.Inner {
		childWrite := childWriteContext(node, i, writeCtx)
		idx.walkBody(&node.Inner[i], source, childWrite, info, seenCalls)
	}
}

func childWriteContext(parent *astNode, childIndex int, current bool) bool {
	if current {
		switch parent.Kind {
		case "ImplicitCastExpr", "CStyleCastExpr", "CXXStaticCastExpr", "CXXReinterpretCastExpr",
			"ParenExpr", "ArraySubscriptExpr", "MemberExpr", "UnaryOperator":
			return true
		}
	}
	if parent.Kind == "BinaryOperator" && isAssignmentOpcode(parent.Opcode) && childIndex == 0 {
		return true
	}
	if parent.Kind == "CompoundAssignOperator" && childIndex == 0 {
		return true
	}
	if parent.Kind == "UnaryOperator" && (parent.Opcode == "++" || parent.Opcode == "--") {
		return true
	}
	return false
}

func isAssignmentOpcode(opcode string) bool {
	switch opcode {
	case "=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=":
		return true
	default:
		return false
	}
}

func findDirectCallee(node *astNode) (CallRef, bool) {
	call := CallRef{Direct: true}
	for i := range node.Inner {
		child := &node.Inner[i]
		for _, candidate := range flattenCallee(child) {
			if candidate.Kind == "MemberExpr" && candidate.Name != "" {
				call.Name = candidate.Name
				if candidate.ReferencedDecl != nil {
					call.Symbol = candidate.ReferencedDecl.MangledName
					if call.Symbol == "" {
						call.Symbol = candidate.ReferencedDecl.Name
					}
					call.Name = candidate.ReferencedDecl.Name
				}
				if call.Symbol == "" {
					call.Symbol = call.Name
				}
				return call, true
			}
			if candidate.ReferencedDecl != nil {
				kind := candidate.ReferencedDecl.Kind
				if kind == "FunctionDecl" || strings.Contains(kind, "Method") || kind == "CXXConstructorDecl" {
					call.Name = candidate.ReferencedDecl.Name
					call.Symbol = candidate.ReferencedDecl.MangledName
					if call.Symbol == "" {
						call.Symbol = call.Name
					}
					return call, true
				}
			}
		}
		break
	}
	if node.Kind == "CXXConstructExpr" {
		name := constructorName(node.Type.QualType)
		if name != "" {
			call.Name = name
			call.Symbol = name
			return call, true
		}
	}
	return CallRef{}, false
}

func flattenCallee(node *astNode) []*astNode {
	var out []*astNode
	var walk func(*astNode)
	walk = func(n *astNode) {
		out = append(out, n)
		switch n.Kind {
		case "ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "CXXStaticCastExpr",
			"CXXReinterpretCastExpr", "CXXBindTemporaryExpr", "MaterializeTemporaryExpr":
			if len(n.Inner) > 0 {
				walk(&n.Inner[0])
			}
		}
	}
	walk(node)
	return out
}

func constructorName(typeName string) string {
	typeName = strings.TrimSpace(typeName)
	if idx := strings.Index(typeName, "<"); idx >= 0 {
		typeName = typeName[:idx]
	}
	parts := strings.Fields(typeName)
	if len(parts) == 0 {
		return ""
	}
	name := parts[len(parts)-1]
	name = strings.TrimPrefix(name, "class ")
	name = strings.TrimPrefix(name, "struct ")
	return name
}

func indirectDescription(node *astNode) string {
	if len(node.Inner) == 0 {
		return ""
	}
	callee := &node.Inner[0]
	if callee.Kind == "DeclRefExpr" && callee.ReferencedDecl != nil {
		return callee.ReferencedDecl.Kind + ":" + callee.ReferencedDecl.Name
	}
	if callee.Type.QualType != "" {
		return callee.Kind + ":" + callee.Type.QualType
	}
	return callee.Kind
}

func hardwareFlagsForCall(name string) map[string]string {
	flags := map[string]string{}
	upper := strings.ToUpper(name)
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "HAL_"), strings.HasPrefix(name, "LL_"):
		flags["HAL_EXTERNAL"] = "known HAL namespace call: " + name
	case strings.HasPrefix(name, "DMA_"), strings.HasPrefix(lower, "dma_"), strings.Contains(lower, "dma"):
		flags["DMA_ASYNC"] = "DMA-related call: " + name
	case strings.Contains(upper, "IRQ"), strings.Contains(upper, "ISR"), strings.HasSuffix(upper, "_HANDLER"):
		flags["ISR_ENTRY"] = "interrupt-related call: " + name
	}
	if strings.HasPrefix(name, "xTask") || strings.HasPrefix(name, "vTask") ||
		strings.HasPrefix(name, "osThread") || strings.HasPrefix(name, "osMutex") ||
		strings.HasPrefix(name, "pthread_") || strings.HasPrefix(lower, "mutex_") ||
		strings.HasPrefix(lower, "sem_") || strings.HasPrefix(name, "k_") ||
		strings.HasPrefix(name, "NVIC_") || strings.HasPrefix(name, "__disable_irq") ||
		strings.HasPrefix(name, "__enable_irq") {
		flags["RTOS_CONTEXT"] = "RTOS/scheduler primitive call: " + name
	}
	return flags
}

func (idx *astIndex) qualifiedName(node *astNode, parentCtx string) string {
	if node.ParentDeclContextID != "" {
		if context := idx.contexts[node.ParentDeclContextID]; context != "" {
			return joinQualified(context, node.Name)
		}
	}
	return joinQualified(parentCtx, node.Name)
}

func (idx *astIndex) resolveFile(raw string) string {
	if raw == "" || strings.HasPrefix(raw, "<") {
		return ""
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(idx.directory, path)
	}
	return filepath.Clean(path)
}

func isFunctionKind(kind string) bool {
	switch kind {
	case "FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl":
		return true
	default:
		return false
	}
}

func isMethodKind(kind string) bool {
	switch kind {
	case "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl":
		return true
	default:
		return false
	}
}

func isContextKind(kind string) bool {
	switch kind {
	case "NamespaceDecl", "CXXRecordDecl", "RecordDecl", "ClassTemplateDecl", "ClassTemplatePartialSpecializationDecl":
		return true
	default:
		return false
	}
}

func isCallKind(kind string) bool {
	return strings.HasSuffix(kind, "CallExpr") || kind == "CXXConstructExpr"
}

func joinQualified(parent, name string) string {
	if parent == "" {
		return name
	}
	if name == "" {
		return parent
	}
	return parent + "::" + name
}

func sortedKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sourceLocation(source string, node *astNode) string {
	if node.Loc.line() > 0 {
		return fmt.Sprintf("%s:%d", source, node.Loc.line())
	}
	return source
}

func astValueString(node *astNode) string {
	if len(node.Value) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(node.Value, &text); err == nil {
		return text
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(node.Value))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		return number.String()
	}
	return ""
}
