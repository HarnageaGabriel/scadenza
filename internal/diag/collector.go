package diag

import "sync"

// Collector safely accumulates diagnostics in insertion order.
type Collector struct {
	mu    sync.Mutex
	items []Diagnostic
}

// Add appends a diagnostic.
func (c *Collector) Add(d Diagnostic) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, d)
}

// List returns a snapshot of collected diagnostics.
func (c *Collector) List() []Diagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Diagnostic(nil), c.items...)
}
