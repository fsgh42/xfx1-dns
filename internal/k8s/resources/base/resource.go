// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package base

import (
	"encoding/json"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
)

type (
	Labels      map[string]string
	Annotations map[string]string

	// Metadata is standard K8s object metadata
	Metadata struct {
		Name        string      `json:"name"`
		Namespace   string      `json:"namespace,omitempty"`
		UID         string      `json:"uid,omitempty"` // Set by K8s on read
		Labels      Labels      `json:"labels,omitempty"`
		Annotations Annotations `json:"annotations,omitempty"`
	}

	// KubernetesObject is the interface for all K8s objects
	KubernetesObject interface {
		GetMetadata() *Metadata
		GetKind() string
		GetAPIVersion() string
	}

	// ObjectMeta is the base struct for K8s objects (legacy, kept for compatibility)
	ObjectMeta struct {
		APIVersion string   `json:"apiVersion"`
		Kind       string   `json:"kind"`
		Metadata   Metadata `json:"metadata"`
	}

	// Object is a generic Kubernetes object for CRDs
	Object[T any] struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Metadata   Metadata        `json:"metadata"`
		Spec       T               `json:"spec"`
		Status     json.RawMessage `json:"status,omitempty"` // Optional, for reads
	}
)

// ObjectMeta implements KubernetesObject
func (o *ObjectMeta) GetMetadata() *Metadata { return &o.Metadata }
func (o *ObjectMeta) GetKind() string        { return o.Kind }
func (o *ObjectMeta) GetAPIVersion() string  { return o.APIVersion }

// Object[T] implements KubernetesObject
func (o *Object[T]) GetMetadata() *Metadata { return &o.Metadata }
func (o *Object[T]) GetKind() string        { return o.Kind }
func (o *Object[T]) GetAPIVersion() string  { return o.APIVersion }

// NewObject creates a K8s object from a spec type.
// Uses the registry to automatically fill APIVersion and Kind.
// Panics if the spec type is not registered.
func NewObject[T any](name, namespace string, spec T) *Object[T] {
	meta := api.MetaFor[T]()
	if meta == nil {
		panic("spec type not registered: use api.RegisterSpec first")
	}

	ns := namespace
	if ns == "" && meta.Namespace != "" {
		ns = meta.Namespace // Use default namespace from registration
	}

	return &Object[T]{
		APIVersion: meta.APIVersion(),
		Kind:       meta.Kind,
		Metadata:   Metadata{Name: name, Namespace: ns},
		Spec:       spec,
	}
}

// NewObjectWithMetadata creates a K8s object with full metadata control.
// Panics if the spec type is not registered.
func NewObjectWithMetadata[T any](md Metadata, spec T) *Object[T] {
	meta := api.MetaFor[T]()
	if meta == nil {
		panic("spec type not registered")
	}

	if md.Namespace == "" && meta.Namespace != "" {
		md.Namespace = meta.Namespace
	}

	return &Object[T]{
		APIVersion: meta.APIVersion(),
		Kind:       meta.Kind,
		Metadata:   md,
		Spec:       spec,
	}
}
