// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

// Package api provides a type-indexed registry mapping Go spec types to their
// Kubernetes API metadata (group, version, kind, resource type).
//
// Consumer packages call RegisterSpec[T] from an init() function
// to wire up the mapping once at startup.
// Callers then use ParamsFor[T] to retrieve ApiRequestParams
// without repeating the metadata.
package api

import (
	"fmt"
	"reflect"
)

// ResourceMeta contains K8s API metadata for a spec type
type ResourceMeta struct {
	Group        string // e.g., "dns.xfx1.de" (empty for core API)
	Version      string // e.g., "v1"
	Kind         string // e.g., "NodeAllocation"
	ResourceType string // e.g., "nodeallocations" (plural)
	Namespace    string // Default namespace (optional)
}

// APIVersion returns the full apiVersion string
func (m *ResourceMeta) APIVersion() string {
	if m.Group == "" {
		return m.Version
	}

	return m.Group + "/" + m.Version
}

// ToParams creates ApiRequestParams for this resource
func (m *ResourceMeta) ToParams() *ApiRequestParams {
	return &ApiRequestParams{
		Group:        m.Group,
		Version:      m.Version,
		ResourceType: m.ResourceType,
		Namespace:    m.Namespace,
	}
}

var specRegistry = map[reflect.Type]*ResourceMeta{}

// RegisterSpec registers a spec type with its K8s metadata
func RegisterSpec[T any](meta *ResourceMeta) {
	var zero T

	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	specRegistry[t] = meta
}

// MetaFor returns the K8s metadata for a spec type
func MetaFor[T any]() *ResourceMeta {
	var zero T

	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	return specRegistry[t]
}

// ParamsFor returns ApiRequestParams for querying a spec type.
// Returns an error if the type is not registered.
func ParamsFor[T any]() (*ApiRequestParams, error) {
	meta := MetaFor[T]()
	if meta == nil {
		var zero T
		return nil, fmt.Errorf("type %T not registered in API registry", zero)
	}

	return meta.ToParams(), nil
}
