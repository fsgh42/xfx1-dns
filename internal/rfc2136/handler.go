// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"context"
	"fmt"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

const (
	sourceLabel      = "dns.xfx1.de/source"
	sourceLabelValue = "rfc2136"
)

// Handler translates DNS UPDATE operations into k8s DNSRecord CR operations.
type Handler struct {
	namespace string
	zone      rec.Domain
	k8s       client.K8sClient
	logger    log.Logger

	updatesTotal    *metrics.Counter
	updateErrors    *metrics.Counter
	crNameOverflows *metrics.Counter
}

// NewHandler creates a new Handler.
func NewHandler(
	namespace string,
	zone rec.Domain,
	k8sClient client.K8sClient,
	logger log.Logger,
	updatesTotal, updateErrors, crNameOverflows *metrics.Counter,
) *Handler {
	return &Handler{
		namespace:       namespace,
		zone:            zone,
		k8s:             k8sClient,
		logger:          logger,
		updatesTotal:    updatesTotal,
		updateErrors:    updateErrors,
		crNameOverflows: crNameOverflows,
	}
}

// HandleUpdate processes a parsed DNS UPDATE message and returns the RCODE to send.
// Prerequisites that are non-empty cause NOTIMP to be returned.
func (h *Handler) HandleUpdate(ctx context.Context, msg *Message) uint8 {
	if len(msg.Prerequisites) > 0 {
		h.logger.Info("unsupported prerequisites in UPDATE message")

		return RcodeNotimp
	}

	// Validate zone
	if msg.Zone != nil && !h.matchesZone(msg.Zone.Name) {
		h.logger.Info(
			fmt.Sprintf(
				"zone mismatch: got %s, expected %s",
				msg.Zone.Name,
				h.zone,
			),
		)
		h.updateErrors.Inc("zone")

		return RcodeNotZone
	}

	for _, rr := range msg.Updates {
		if err := h.processUpdate(ctx, rr); err != nil {
			h.logger.Error(fmt.Sprintf("process update: %v", err))

			return RcodeServFail
		}
	}

	return RcodeNoError
}

func (h *Handler) matchesZone(name string) bool {
	return strings.EqualFold(
		strings.TrimSuffix(name, "."),
		strings.TrimSuffix(string(h.zone), "."),
	)
}

// processUpdate handles a single RR from the update section per RFC 2136 §2.5.
func (h *Handler) processUpdate(ctx context.Context, rr *RR) error {
	// Delete all RRsets at name (RFC 2136 §2.5.3): CLASS=ANY, TTL=0, TYPE=ANY(255), RDLENGTH=0.
	// Handled before the RRtype lookup because type 255 (ANY) is not in RRtypeFromWire.
	if rr.Class == ClassANY && rr.TTL == 0 && rr.Type == 255 &&
		rr.Rdlength == 0 {
		return h.deleteAllAtName(ctx, rr.Name)
	}

	rrtype, ok := rec.RRtypeFromWire[rr.Type]
	if !ok {
		// Unknown type — skip silently (spec says ignore unknown types in ADD)
		h.logger.Info(fmt.Sprintf("unknown RR type %d, skipping", rr.Type))

		return nil
	}

	fqdn := rr.Name
	rrtypeStr := string(rrtype)

	switch {
	case rr.Class == ClassIN:
		// Add RR (RFC 2136 §2.5.1: TTL >= 0)
		return h.addRR(ctx, fqdn, rrtypeStr, rr.Rdata)

	case rr.Class == ClassANY && rr.TTL == 0 && rr.Rdlength == 0:
		// Delete RRset (all RRs with name+type)
		return h.deleteRRset(ctx, fqdn, rrtypeStr)

	case rr.Class == ClassNONE && rr.TTL == 0:
		// Delete specific RR
		return h.deleteRR(ctx, fqdn, rrtypeStr, rr.Rdata)

	default:
		h.logger.Info(
			"unrecognised update combination",
			log.Ctx{
				"class": rr.Class,
				"ttl":   rr.TTL,
				"type":  rr.Type,
				"rdlen": rr.Rdlength,
			},
		)

		return nil
	}
}
