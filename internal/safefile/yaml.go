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
	if err := checkYAMLDepth(&node, 1); err != nil {
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

// checkYAMLDepth rejects a document that nests deeper than MaxYAMLDepth. The
// walk stops at the first level that is too deep, so the recursion never
// grows with the depth of the document.
func checkYAMLDepth(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := checkYAMLDepth(child, depth); err != nil {
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
			if err := checkYAMLDepth(node.Content[index+1], depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if depth > MaxYAMLDepth {
			return fmt.Errorf("the document nests deeper than %d levels", MaxYAMLDepth)
		}
		for _, child := range node.Content {
			if err := checkYAMLDepth(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
