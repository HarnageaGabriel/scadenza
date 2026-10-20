package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// finding is one difference between the old and the new schema.
type finding struct {
	path   string
	reason string
	note   bool
}

// comparator compares two schema documents.
type comparator struct {
	old      *document
	new      *document
	findings []finding
	visited  map[string]bool
}

// diff compares two schema documents and returns the differences.
func diff(old, updated *document) []finding {
	c := &comparator{old: old, new: updated, visited: map[string]bool{}}
	c.compareSchemas("", old.root, updated.root)
	c.compareDefinitions()
	return c.findings
}

// compareSchemas compares two schema nodes. References to local definitions
// are resolved before the comparison.
func (c *comparator) compareSchemas(path string, old, updated map[string]any) {
	oldSchema, oldRef, oldStatus := c.old.resolve(old)
	updatedSchema, newRef, newStatus := c.new.resolve(updated)
	switch {
	case oldStatus == refExternal || newStatus == refExternal:
		oldText, newText := refText(old), refText(updated)
		if oldText != newText {
			c.breakf(path, "reference changed from %s to %s", oldText, newText)
		}
		return
	case oldStatus == refMissing:
		c.breakf(path, "reference %s has no target in the old schema", refText(old))
		return
	case newStatus == refMissing:
		if !c.removedDefinition(newRef) {
			c.breakf(path, "reference %s has no target in the new schema", refText(updated))
		}
		return
	}
	if oldStatus == refResolved || newStatus == refResolved {
		key := oldRef + "\x00" + newRef
		if c.visited[key] {
			return
		}
		c.visited[key] = true
	}
	c.compareKeywords(path, oldSchema, updatedSchema)
}

// compareKeywords compares the keywords of two schema nodes.
func (c *comparator) compareKeywords(path string, old, updated map[string]any) {
	c.compareTypes(path, old, updated)
	c.compareProperties(path, old, updated)
	c.compareRequired(path, old, updated)
	c.compareEnum(path, old, updated)
	c.compareConst(path, old, updated)
	c.comparePattern(path, old, updated)
	c.compareBounds(path, old, updated)
	c.compareAdditionalProperties(path, old, updated)
	c.compareItems(path, old, updated)
	c.compareBranches(path, old, updated)
}

// compareTypes checks that the new type list still accepts every type the old
// one accepted. A type list may gain members, never lose any.
func (c *comparator) compareTypes(path string, old, updated map[string]any) {
	oldTypes, oldHas := typeList(old)
	newTypes, newHas := typeList(updated)
	switch {
	case !oldHas && !newHas:
		return
	case oldHas && !newHas:
		// The new schema accepts every type: the constraint got looser.
		return
	case !oldHas && newHas:
		c.breakf(path, "type constraint added: %s", quoteList(newTypes))
		return
	}
	for _, oldType := range oldTypes {
		if acceptsType(newTypes, oldType) {
			continue
		}
		c.breakf(path, "type changed: %s is no longer accepted (was %s, now %s)",
			strconv.Quote(oldType), quoteList(oldTypes), quoteList(newTypes))
		return
	}
}

// compareProperties checks that no property was removed and compares the
// properties that stayed.
func (c *comparator) compareProperties(path string, old, updated map[string]any) {
	oldProps := propertyMap(old)
	newProps := propertyMap(updated)
	for _, name := range sortedNames(oldProps) {
		child, ok := newProps[name]
		if !ok {
			c.breakf(childPath(path, "properties")+"/"+escapePointer(name), "property removed")
			continue
		}
		c.compareSchemas(childPath(path, "properties")+"/"+escapePointer(name), oldProps[name], child)
	}
}

// compareRequired reports the changes to the required list. Decision 1 of
// ADR 0007 allows a name to be added to the required list and allows a
// required name to be dropped, so both are notes and neither fails the run.
func (c *comparator) compareRequired(path string, old, updated map[string]any) {
	oldRequired := stringSet(old["required"])
	newRequired := stringSet(updated["required"])
	oldProps := propertyMap(old)
	newProps := propertyMap(updated)
	for _, name := range sortedNames(newRequired) {
		if oldRequired[name] {
			continue
		}
		location := childPath(path, "required")
		if _, ok := newProps[name]; ok {
			location = childPath(childPath(path, "properties"), escapePointer(name))
		}
		if _, existed := oldProps[name]; existed {
			c.notef(location, "property changed from optional to required")
			continue
		}
		c.notef(location, "new required property")
	}
	for _, name := range sortedNames(oldRequired) {
		if newRequired[name] {
			continue
		}
		if _, kept := newProps[name]; !kept {
			// The property itself is gone, which compareProperties already
			// reports as a break.
			continue
		}
		location := childPath(childPath(path, "properties"), escapePointer(name))
		c.notef(location, "property changed from required to optional; "+
			"consumers relying on presence may be affected")
	}
}

// compareEnum checks that no enum value was removed. A new value is allowed
// by ADR 0007 and is reported as a note.
func (c *comparator) compareEnum(path string, old, updated map[string]any) {
	oldValues, oldHas := enumValues(old)
	newValues, newHas := enumValues(updated)
	switch {
	case !oldHas && !newHas:
		return
	case oldHas && !newHas:
		// The new schema accepts every value: the constraint got looser.
		return
	case !oldHas && newHas:
		c.breakf(path, "enum constraint added: %s", formatValues(newValues))
		return
	}
	oldSet := valueSet(oldValues)
	newSet := valueSet(newValues)
	for _, value := range oldValues {
		if !newSet[valueKey(value)] {
			c.breakf(path, "enum value %s removed", formatValue(value))
		}
	}
	for _, value := range newValues {
		if !oldSet[valueKey(value)] {
			c.notef(path, "enum value %s added", formatValue(value))
		}
	}
}

// compareConst checks that a const value did not change.
func (c *comparator) compareConst(path string, old, updated map[string]any) {
	oldConst, oldHas := old["const"]
	newConst, newHas := updated["const"]
	switch {
	case oldHas && newHas:
		if valueKey(oldConst) != valueKey(newConst) {
			c.breakf(path, "const changed from %s to %s", formatValue(oldConst), formatValue(newConst))
		}
	case !oldHas && newHas:
		c.breakf(path, "const added: %s", formatValue(newConst))
	}
}

// comparePattern checks that a pattern did not become stricter.
func (c *comparator) comparePattern(path string, old, updated map[string]any) {
	oldPattern, oldHas := old["pattern"].(string)
	newPattern, newHas := updated["pattern"].(string)
	switch {
	case !oldHas && !newHas:
		return
	case !oldHas && newHas:
		c.breakf(path, "pattern added: %s", strconv.Quote(newPattern))
	case oldHas && !newHas:
		// The new schema accepts every string: the constraint got looser.
	case oldPattern == newPattern:
	case patternLooser(oldPattern, newPattern):
		// The new pattern accepts every string the old one accepted.
	default:
		c.breakf(path, "pattern changed from %s to %s and the new one is not provably looser",
			strconv.Quote(oldPattern), strconv.Quote(newPattern))
	}
}

// compareBounds checks that the numeric and length limits did not become
// stricter.
func (c *comparator) compareBounds(path string, old, updated map[string]any) {
	c.compareLowerBound(path, old, updated, "minimum")
	c.compareUpperBound(path, old, updated, "maximum")
	c.compareLowerBound(path, old, updated, "minLength")
	c.compareUpperBound(path, old, updated, "maxLength")
}

func (c *comparator) compareLowerBound(path string, old, updated map[string]any, keyword string) {
	oldValue, oldHas := numberValue(old[keyword])
	newValue, newHas := numberValue(updated[keyword])
	switch {
	case !oldHas && !newHas:
		return
	case !oldHas && newHas:
		c.breakf(path, "%s added: %s", keyword, formatNumber(newValue))
	case oldHas && !newHas:
		// The new schema accepts every value: the constraint got looser.
	case newValue > oldValue:
		c.breakf(path, "%s increased from %s to %s", keyword, formatNumber(oldValue), formatNumber(newValue))
	}
}

func (c *comparator) compareUpperBound(path string, old, updated map[string]any, keyword string) {
	oldValue, oldHas := numberValue(old[keyword])
	newValue, newHas := numberValue(updated[keyword])
	switch {
	case !oldHas && !newHas:
		return
	case !oldHas && newHas:
		c.breakf(path, "%s added: %s", keyword, formatNumber(newValue))
	case oldHas && !newHas:
		// The new schema accepts every value: the constraint got looser.
	case newValue < oldValue:
		c.breakf(path, "%s decreased from %s to %s", keyword, formatNumber(oldValue), formatNumber(newValue))
	}
}

// compareAdditionalProperties checks that an object that allowed extra
// fields did not start to forbid them.
func (c *comparator) compareAdditionalProperties(path string, old, updated map[string]any) {
	oldValue, oldHas := old["additionalProperties"]
	newValue, newHas := updated["additionalProperties"]
	oldForbidden := oldHas && oldValue == false
	newForbidden := newHas && newValue == false
	oldSchema, oldIsSchema := oldValue.(map[string]any)
	newSchema, newIsSchema := newValue.(map[string]any)
	switch {
	case oldForbidden && newForbidden:
		return
	case oldForbidden && !newForbidden:
		// Extra fields are allowed again: the constraint got looser.
		return
	case !oldForbidden && newForbidden:
		if oldIsSchema {
			c.breakf(path, "additionalProperties changed from a schema to false")
			return
		}
		c.breakf(path, "additionalProperties changed from allowed to false")
		return
	}
	switch {
	case oldIsSchema && newIsSchema:
		c.compareSchemas(childPath(path, "additionalProperties"), oldSchema, newSchema)
	case !oldIsSchema && newIsSchema:
		c.breakf(path, "additionalProperties became constrained by a schema")
	}
}

// compareItems checks that the items of an array did not become stricter.
func (c *comparator) compareItems(path string, old, updated map[string]any) {
	oldItems, oldHas := old["items"].(map[string]any)
	newItems, newHas := updated["items"].(map[string]any)
	switch {
	case oldHas && newHas:
		c.compareSchemas(childPath(path, "items"), oldItems, newItems)
	case !oldHas && newHas:
		c.breakf(path, "items constraint added")
	}
}

// compareBranches checks the composed schemas allOf, anyOf and oneOf.
func (c *comparator) compareBranches(path string, old, updated map[string]any) {
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		oldBranches, oldHas := branchList(old[keyword])
		newBranches, newHas := branchList(updated[keyword])
		switch {
		case oldHas && newHas:
			if len(oldBranches) != len(newBranches) {
				c.breakf(path, "%s changed from %d to %d branches", keyword, len(oldBranches), len(newBranches))
				continue
			}
			for index := range oldBranches {
				branch := childPath(childPath(path, keyword), strconv.Itoa(index))
				c.compareSchemas(branch, oldBranches[index], newBranches[index])
			}
		case oldHas && !newHas:
			// The new schema accepts every value: the constraint got looser.
		case !oldHas && newHas:
			c.breakf(path, "%s constraint added", keyword)
		}
	}
}

// compareDefinitions reports a definition that was removed while it is still
// referenced.
func (c *comparator) compareDefinitions() {
	oldDefs := c.old.definitions()
	newDefs := c.new.definitions()
	for _, name := range sortedNames(oldDefs) {
		if _, kept := newDefs[name]; kept {
			continue
		}
		sites := c.new.refSites(name)
		if len(sites) == 0 {
			continue
		}
		c.breakf("/"+oldDefs[name].path, "definition removed while still referenced by %s",
			strings.Join(sites, ", "))
	}
}

// removedDefinition reports whether a reference points at a definition that
// the new schema dropped. Such a reference is reported by compareDefinitions
// instead of as a missing target.
func (c *comparator) removedDefinition(ref string) bool {
	newDefs := c.new.definitions()
	for name := range c.old.definitions() {
		if !referencesName(ref, name) {
			continue
		}
		if _, kept := newDefs[name]; !kept {
			return true
		}
	}
	return false
}

func (c *comparator) breakf(path, format string, args ...any) {
	c.findings = append(c.findings, finding{path: path, reason: fmt.Sprintf(format, args...)})
}

func (c *comparator) notef(path, format string, args ...any) {
	c.findings = append(c.findings, finding{path: path, reason: fmt.Sprintf(format, args...), note: true})
}

// typeList returns the types a schema accepts.
func typeList(schema map[string]any) ([]string, bool) {
	switch value := schema["type"].(type) {
	case string:
		return []string{value}, true
	case []any:
		types := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				types = append(types, text)
			}
		}
		return types, true
	}
	return nil, false
}

// acceptsType reports whether the type list still accepts the given type.
func acceptsType(types []string, oldType string) bool {
	for _, candidate := range types {
		if candidate == oldType {
			return true
		}
		if oldType == "integer" && candidate == "number" {
			return true
		}
	}
	return false
}

// propertyMap returns the properties of a schema.
func propertyMap(schema map[string]any) map[string]map[string]any {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return map[string]map[string]any{}
	}
	result := make(map[string]map[string]any, len(properties))
	for name, value := range properties {
		if child, ok := value.(map[string]any); ok {
			result[name] = child
		}
	}
	return result
}

// stringSet returns a set of the strings in a decoded JSON array.
func stringSet(value any) map[string]bool {
	items, ok := value.([]any)
	if !ok {
		return map[string]bool{}
	}
	result := make(map[string]bool, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result[text] = true
		}
	}
	return result
}

// enumValues returns the values of an enum keyword.
func enumValues(schema map[string]any) ([]any, bool) {
	values, ok := schema["enum"].([]any)
	return values, ok
}

// branchList returns the branches of a composed schema keyword.
func branchList(value any) ([]map[string]any, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		branch, ok := item.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, branch)
	}
	return result, true
}

// numberValue returns a numeric keyword of a schema.
func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	case float64:
		return typed, true
	}
	return 0, false
}

// valueKey returns a comparable key for a decoded JSON value.
func valueKey(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

// valueSet returns the keys of a list of decoded JSON values.
func valueSet(values []any) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[valueKey(value)] = true
	}
	return result
}

// formatValue renders a decoded JSON value.
func formatValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

// formatValues renders a list of decoded JSON values.
func formatValues(values []any) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, formatValue(value))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// formatNumber renders a numeric keyword value.
func formatNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// quoteList renders a list of type names.
func quoteList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Quote(value))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// refText renders the reference of a schema node.
func refText(schema map[string]any) string {
	if ref, ok := schema["$ref"].(string); ok {
		return strconv.Quote(ref)
	}
	return "an inline schema"
}

// sortedNames returns the keys of a map in a stable order.
func sortedNames[V any](values map[string]V) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// patternLooser reports whether the new pattern accepts every string the old
// pattern accepts. Only two cases are provable: a new pattern that keeps every
// alternative of the old one, and a new pattern that matches the literal text
// of an anchored literal old pattern.
func patternLooser(oldPattern, newPattern string) bool {
	oldParts := splitAlternatives(oldPattern)
	newParts := splitAlternatives(newPattern)
	if len(oldParts) > 1 || len(newParts) > 1 {
		for _, part := range oldParts {
			if !slices.Contains(newParts, part) {
				return false
			}
		}
		return true
	}
	literal, ok := literalPattern(oldPattern)
	if !ok {
		return false
	}
	matched, err := regexp.MatchString(newPattern, literal)
	if err != nil {
		return false
	}
	return matched
}

// splitAlternatives splits a regular expression at its top level "|".
func splitAlternatives(pattern string) []string {
	var parts []string
	depth := 0
	inClass := false
	escaped := false
	start := 0
	for index, char := range pattern {
		switch {
		case escaped:
			escaped = false
		case char == '\\':
			escaped = true
		case inClass:
			if char == ']' {
				inClass = false
			}
		case char == '[':
			inClass = true
		case char == '(':
			depth++
		case char == ')':
			depth--
		case char == '|' && depth == 0:
			parts = append(parts, pattern[start:index])
			start = index + 1
		}
	}
	return append(parts, pattern[start:])
}

// literalPattern returns the literal text of an anchored literal pattern.
func literalPattern(pattern string) (string, bool) {
	if len(pattern) < 2 || !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		return "", false
	}
	body := pattern[1 : len(pattern)-1]
	if strings.ContainsAny(body, `\.+*?()|[]{}^$`) {
		return "", false
	}
	return body, true
}
