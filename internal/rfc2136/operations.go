// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"context"
	"fmt"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// addRR creates or updates a DNSRecord CR for the given RR.
func (h *Handler) addRR(
	ctx context.Context,
	fqdn, rrtype string,
	rdata []byte,
) error {
	crName, err := CRName(sourceLabelValue, rrtype, fqdn, rdata)
	if err != nil {
		h.logger.Error(err.Error())
		h.crNameOverflows.Inc()
		h.updateErrors.Inc("overflow")

		return err
	}

	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return err
	}

	p.Namespace = h.namespace
	p.Name = crName
	p.FieldManager = "rfc2136"

	// Build the DNSRecord object from the raw rdata bytes.
	rrOpts, err := rec.ParseRdata(rec.RRtype(rrtype), rdata)
	if err != nil {
		return fmt.Errorf("ParseRdata: %w", err)
	}

	rrSpec := rec.RR{
		Name:   rec.Domain(fqdn),
		RRtype: rec.RRtype(rrtype),
		TTL:    60,
		Opts:   rrOpts,
	}

	obj := base.NewObjectWithMetadata[rec.RR](
		base.Metadata{
			Name:      crName,
			Namespace: h.namespace,
			Labels:    base.Labels{sourceLabel: sourceLabelValue},
		},
		rrSpec,
	)

	if err := h.k8s.ApplyOrUpdate(ctx, p, obj); err != nil {
		h.updateErrors.Inc("k8s")

		return fmt.Errorf("ApplyOrUpdate %s: %w", crName, err)
	}

	h.updatesTotal.Inc("add")
	h.logger.Info("added CR", log.Ctx{"name": crName})

	return nil
}

// deleteRRset deletes all DNSRecord CRs for the given name+rrtype.
func (h *Handler) deleteRRset(ctx context.Context, fqdn, rrtype string) error {
	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return err
	}

	p.Namespace = h.namespace
	p.LabelSelector = []string{sourceLabel + "=" + sourceLabelValue}

	objects, err := client.QueryApiWithParams[rec.RR](ctx, h.k8s, p)
	if err != nil && err != client.ErrNoResults {
		h.updateErrors.Inc("k8s")
		return fmt.Errorf("list CRs: %w", err)
	}

	for _, obj := range objects {
		if !strings.EqualFold(string(obj.Spec.Name), fqdn) {
			continue
		}

		if !strings.EqualFold(string(obj.Spec.RRtype), rrtype) {
			continue
		}

		if err := h.deleteCR(ctx, obj.Metadata.Name); err != nil {
			return err
		}
	}

	h.updatesTotal.Inc("delete_rrset")

	return nil
}

// deleteAllAtName deletes all DNSRecord CRs for the given name.
func (h *Handler) deleteAllAtName(ctx context.Context, fqdn string) error {
	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return err
	}

	p.Namespace = h.namespace
	p.LabelSelector = []string{sourceLabel + "=" + sourceLabelValue}

	objects, err := client.QueryApiWithParams[rec.RR](ctx, h.k8s, p)
	if err != nil && err != client.ErrNoResults {
		h.updateErrors.Inc("k8s")

		return fmt.Errorf("list CRs: %w", err)
	}

	for _, obj := range objects {
		if !strings.EqualFold(string(obj.Spec.Name), fqdn) {
			continue
		}

		if err := h.deleteCR(ctx, obj.Metadata.Name); err != nil {
			return err
		}
	}

	h.updatesTotal.Inc("delete_name")

	return nil
}

// deleteRR deletes a single DNSRecord CR for the given name+rrtype+rdata.
func (h *Handler) deleteRR(
	ctx context.Context,
	fqdn, rrtype string,
	rdata []byte,
) error {
	crName, err := CRName(sourceLabelValue, rrtype, fqdn, rdata)
	if err != nil {
		h.logger.Error(err.Error())
		h.crNameOverflows.Inc()
		h.updateErrors.Inc("overflow")

		return err
	}

	if err := h.deleteCR(ctx, crName); err != nil {
		return err
	}

	h.updatesTotal.Inc("delete_rr")

	return nil
}

// deleteCR deletes a DNSRecord CR by name (404 = already gone = success).
func (h *Handler) deleteCR(ctx context.Context, crName string) error {
	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return err
	}

	p.Namespace = h.namespace
	p.Name = crName

	if err := h.k8s.Delete(ctx, p); err != nil {
		h.updateErrors.Inc("k8s")

		return fmt.Errorf("delete CR %s: %w", crName, err)
	}

	h.logger.Info("deleted CR", log.Ctx{"name": crName})

	return nil
}
