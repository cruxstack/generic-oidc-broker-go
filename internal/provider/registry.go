package provider

import (
	"net/http"
	"slices"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// Registry holds the configured providers by name.
type Registry struct {
	byName map[string]*Provider
	names  []string
}

// NewRegistry creates a provider for each configuration. Names must be
// unique, which config.Validate ensures.
func NewRegistry(cfgs []config.Provider, httpClient *http.Client) (*Registry, error) {
	r := &Registry{byName: make(map[string]*Provider, len(cfgs))}
	for _, cfg := range cfgs {
		p, err := New(cfg, httpClient)
		if err != nil {
			return nil, err
		}
		r.byName[cfg.Name] = p
		r.names = append(r.names, cfg.Name)
	}
	slices.Sort(r.names)
	return r, nil
}

// Get returns the named provider, or nil if there is none.
func (r *Registry) Get(name string) *Provider {
	return r.byName[name]
}

// Names returns the provider names in sorted order.
func (r *Registry) Names() []string {
	return slices.Clone(r.names)
}
