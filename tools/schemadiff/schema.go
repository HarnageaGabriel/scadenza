package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// definitionContainers are the schema keywords that hold reusable
// definitions. Draft 2020-12 calls the section "$defs"; the older "definitions"
// and the informal "defs" are accepted as well.
var definitionContainers = []string{"$defs", "definitions", "defs"}

// document is one parsed JSON Schema file.
type document struct {
	root map[string]any
}

// definition is one reusable definition of a document.
type definition struct {
	name   string
	path   string
	schema map[string]any
}

func loadDocument(path string) (*document, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator picks the schema files
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &document{root: root}, nil
}

// definitions returns the reusable definitions of the document, keyed by name.
func (d *document) definitions() map[string]definition {
	result := map[string]definition{}
	for _, container := range definitionContainers {
		group, ok := d.root[container].(map[string]any)
		if !ok {
			continue
		}
		for name, value := range group {
			schema, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if _, seen := result[name]; seen {
				continue
			}
			result[name] = definition{name: name, path: container + "/" + name, schema: schema}
		}
	}
	return result
}

// refSites returns the JSON pointers of the places that reference the named
// definition.
func (d *document) refSites(name string) []string {
	var sites []string
	walk(d.root, "", func(path string, node any) {
		schema, ok := node.(map[string]any)
		if !ok {
			return
		}
		ref, ok := schema["$ref"].(string)
		if ok && referencesName(ref, name) {
			sites = append(sites, path)
		}
	})
	slices.Sort(sites)
	return sites
}

// referencesName reports whether the reference points at the named
// definition of one of the definition containers.
func referencesName(ref, name string) bool {
	pointer := strings.TrimPrefix(ref, "#")
	pointer = strings.TrimPrefix(pointer, "/")
	parts := strings.Split(pointer, "/")
	if len(parts) != 2 {
		return false
	}
	if !slices.Contains(definitionContainers, parts[0]) {
		return false
	}
	return unescapePointer(parts[1]) == name
}

// refStatus tells what happened to a "$ref" keyword.
type refStatus int

const (
	refAbsent refStatus = iota
	refResolved
	refExternal
	refMissing
)

// resolve follows a local reference and returns the schema it points at, the
// JSON pointer of that target and the status of the reference.
func (d *document) resolve(schema map[string]any) (map[string]any, string, refStatus) {
	ref, ok := schema["$ref"].(string)
	if !ok {
		return schema, "", refAbsent
	}
	if !strings.HasPrefix(ref, "#") {
		return nil, ref, refExternal
	}
	pointer := strings.TrimPrefix(ref, "#")
	if pointer == "" {
		return d.root, "", refResolved
	}
	target, found := d.lookup(pointer)
	if !found {
		return nil, ref, refMissing
	}
	return target, pointer, refResolved
}

// lookup walks a JSON pointer inside the document.
func (d *document) lookup(pointer string) (map[string]any, bool) {
	current := any(d.root)
	for _, token := range strings.Split(pointer, "/")[1:] {
		name := unescapePointer(token)
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[name]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(name)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	schema, ok := current.(map[string]any)
	return schema, ok
}

// walk visits every node of a decoded JSON document.
func walk(node any, path string, visit func(string, any)) {
	visit(path, node)
	switch typed := node.(type) {
	case map[string]any:
		for name, child := range typed {
			walk(child, childPath(path, escapePointer(name)), visit)
		}
	case []any:
		for index, child := range typed {
			walk(child, childPath(path, strconv.Itoa(index)), visit)
		}
	}
}

// childPath appends a segment to a JSON pointer.
func childPath(parent, segment string) string {
	if parent == "" {
		return "/" + segment
	}
	return parent + "/" + segment
}

// escapePointer escapes a property name for use in a JSON pointer.
func escapePointer(name string) string {
	name = strings.ReplaceAll(name, "~", "~0")
	return strings.ReplaceAll(name, "/", "~1")
}

// unescapePointer reverses escapePointer.
func unescapePointer(name string) string {
	name = strings.ReplaceAll(name, "~1", "/")
	return strings.ReplaceAll(name, "~0", "~")
}
