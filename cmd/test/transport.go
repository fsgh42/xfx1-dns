// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// sendTCP sends a DNS query over TCP with RFC 1035 §4.2.2 two-byte length framing.
func sendTCP(addr string, timeout time.Duration, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if err := writeTCPFrame(conn, msg); err != nil {
		return nil, err
	}

	return readTCPFrame(conn)
}

// sendUDP sends a DNS query over UDP and reads the response.
func sendUDP(addr string, timeout time.Duration, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// sendDoT sends a DNS query via DNS-over-TLS with two-byte length framing.
func sendDoT(
	ctx context.Context,
	addr string,
	tlsCfg *tls.Config,
	timeout time.Duration,
	msg []byte,
) ([]byte, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    tlsCfg,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if err := writeTCPFrame(conn, msg); err != nil {
		return nil, err
	}

	return readTCPFrame(conn)
}

// sendDoH sends a DNS query via DNS-over-HTTPS (RFC 8484).
func sendDoH(
	ctx context.Context,
	url string,
	tlsCfg *tls.Config,
	timeout time.Duration,
	msg []byte,
) ([]byte, error) {
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(msg),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// writeTCPFrame writes a DNS message preceded by a 2-byte big-endian length.
func writeTCPFrame(w io.Writer, msg []byte) error {
	var lenBuf [2]byte

	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	_, err := w.Write(msg)

	return err
}

// readTCPFrame reads a 2-byte length prefix then reads that many bytes.
func readTCPFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte

	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}

	buf := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))

	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// makeTLSConfig builds a *tls.Config for DoH/DoT connections.
// If insecure is true, certificate verification is skipped.
// If caPEM is non-empty it is added as a trusted root; serverName is used for SNI.
func makeTLSConfig(insecure bool, caPEM []byte, serverName string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: insecure, //nolint:gosec // intentional, controlled by TLS_INSECURE env var
		ServerName:         serverName,
	}

	if !insecure && len(caPEM) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		cfg.RootCAs = pool
	}

	return cfg
}

// certServerName extracts the first DNS SAN from a PEM-encoded certificate.
// Falls back to the certificate's Common Name. Returns "" if unparseable.
func certServerName(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}

	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	return cert.Subject.CommonName
}

// dohURL constructs the DNS-over-HTTPS URL for a given host and port.
// IPv6 addresses are bracketed per RFC 3986.
func dohURL(host string, port int) string {
	return fmt.Sprintf(
		"https://%s/dns-query",
		net.JoinHostPort(host, fmt.Sprint(port)),
	)
}

// dnsAddr joins a host and port into an address suitable for net.Dial.
func dnsAddr(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprint(port))
}
