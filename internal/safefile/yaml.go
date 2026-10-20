package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// MaxYAMLDepth is the deepest document nesting the YAML readers accept. The
// root mapping is level one, so a document with MaxYAMLDepth nested mappings
// is accepted and one more is not.
const MaxYAMLDepth = 64

// ErrMultipleDocuments marks an input that holds more than one YAML
// document. The extra document used to be ignored silently.
var ErrMultipleDocuments = errors.New("more than one YAML document")

// DecodeYAML decodes exactly one YAML document from data into value.
//
// The document is parsed into a node tree first, so its nesting depth is known
// before anything is decoded into value: a document nested deeper than
// MaxYAMLDepth is rejected instead of being decoded. A second document in the
// same input is rejected too, instead of being ignored. Unknown keys are
// rejected, so a typo cannot silently disable a setting.
//
// Anchors, aliases and merge keys are rejected as well. The files this reads
// never need them, an alias can expand a document exponentially inside the
// size cap, and a merge key can bring in keys the unknown-key check never
// sees. The error names the line the construct is on.
//
// An empty input leaves value untouched.
func DecodeYAML(data []byte, value any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if err := checkYAMLNode(&node, 1); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return ErrMultipleDocuments
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(value); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// checkYAMLNode rejects a document that uses an anchor, an alias or a merge
// key, and a document that nests deeper than MaxYAMLDepth.
//
// The alias is looked for in a pass of its own: an alias can only appear
// after the anchor it names, so a single pass in document order would always
// report the anchor and never the alias.
func checkYAMLNode(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if line, found := findYAMLAlias(node); found {
		return errYAMLUnsupported(line, "an alias")
	}
	return walkYAMLNode(node, depth)
}

// findYAMLAlias returns the line of the first alias node in the tree.
func findYAMLAlias(node *yaml.Node) (int, bool) {
	if node == nil {
		return 0, false
	}
	if node.Kind == yaml.AliasNode {
		return node.Line, true
	}
	for _, child := range node.Content {
		if line, found := findYAMLAlias(child); found {
			return line, true
		}
	}
	return 0, false
}

// walkYAMLNode rejects a document that uses an anchor or a merge key, and a
// document that nests deeper than MaxYAMLDepth. The walk stops at the first
// level that is too deep, so the recursion never grows with the depth of the
// document.
func walkYAMLNode(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if node.Anchor != "" {
		return errYAMLUnsupported(node.Line, "an anchor")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := walkYAMLNode(child, depth); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if depth > MaxYAMLDepth {
			return fmt.Errorf("the document nests deeper than %d levels", MaxYAMLDepth)
		}
		// A mapping holds alternating keys and values; only the values can
		// nest.
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if isYAMLMergeKey(key) {
				return errYAMLUnsupported(key.Line, "a merge key")
			}
			if err := walkYAMLNode(key, depth); err != nil {
				return err
			}
			if err := walkYAMLNode(node.Content[index+1], depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if depth > MaxYAMLDepth {
			return fmt.Errorf("the document nests deeper than %d levels", MaxYAMLDepth)
		}
		for _, child := range node.Content {
			if err := walkYAMLNode(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// isYAMLMergeKey reports whether a mapping key is the YAML merge key. The
// merge key brings in the keys of another mapping, which the unknown-key
// check would never see.
func isYAMLMergeKey(node *yaml.Node) bool {
	if node.Kind != yaml.ScalarNode || node.Value != "<<" {
		return false
	}
	switch node.Tag {
	case "", "!", "!!merge":
		return true
	}
	return false
}

// errYAMLUnsupported reports a YAML construct the readers do not support,
// naming the line it is on.
func errYAMLUnsupported(line int, construct string) error {
	return fmt.Errorf("line %d: anchors, aliases and merge keys are not supported: the document uses %s", line, construct)
}
