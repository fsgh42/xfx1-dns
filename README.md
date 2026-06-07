# xfx1-dns

A Kubernetes-native authoritative DNS server for private infrastructure.
Built from scratch in Go with zero external dependencies — no DNS library, no Kubernetes client library, no metrics library.

## Use Case

Managing DNS in a Kubernetes cluster where records are defined as CRDs alongside the workloads they serve.
Supports DNSSEC signing, DNS-over-HTTPS, DNS-over-TLS, and Prometheus metrics out of the box.

## Motivation

Why write your own? There are already so many DNS servers out there that solve this problem!

* *the complexity you own is better than the simplicity you rent*
  * `route53` and `AWS` can both GTFO
  * `powerdns` is not trivial to configure, run and maintain
  * `dnsmasq` is not fully featured
  * `bind9` is ancient and not as flexible to configure without nasty hacks
* because I can
* because it *exactly* fits my needs and use case
* this thing has zero golang dependencies, therefore more resilient to supply chain attacks
* built using AI assistance
  * We live in wild times where API contracts could finally replace library dependencies.
    I don't need that `kubectl` library anymore, that adds `20MB` to the compiled executable, *how cool is that*?

## Architecture

Main components (see `cmd/`) run as separate workloads and communicate over HTTP and DNS wire format.

Overview component interaction:

```
[DNSRecord CRD]<--[add/del]--[rfc2136]<--[external actor]
      ^
      |
  read/watch
      |
    [master]<--[DB push/poll]-->[slaves]
       |                           ^
     builds                        |
       |                         query forward
       v                           |
      [DB]                      [routers]
                                   ^
                                   |
                   [client]--query--
```

### Master

Single instance. Watches `DNSRecord` CRDs for changes, rebuilds the entire in-memory database from scratch on any change, runs sanity checks (See [`internal/master/master.go`](internal/master/master.go) for the full list), optionally signs with DNSSEC, and pushes the full database to all slaves. Discovers slave addresses by resolving the headless Kubernetes Service. Re-signs DNSSEC records on a configurable interval (`spec.master.resignInterval`, default: 24h).

### Slave

DaemonSet on worker nodes. Receives full database pushes from master (`POST /db`), falls back to polling master every 60 seconds. Answers DNS queries on port 53 (UDP and TCP). Includes DNSSEC records in responses when the DO bit is set.

### Router

DaemonSet on all nodes with `hostPort 53`, `hostPort 443`, and `hostPort 853`. Client-facing proxy: on each query it resolves slave addresses, forwards the raw DNS wire bytes to **all** slaves in parallel, and returns the first response. Serves four protocols:

- **UDP/TCP** on port 53 (standard DNS)
- **DNS-over-HTTPS** (RFC 8484) on port 443 — works with browsers, curl, and any HTTPS client
- **DNS-over-TLS** (RFC 7858) on port 853 — used by systemd-resolved (`DNSOverTLS=yes`) and Android "Private DNS"

DoH and DoT share the same TLS certificate (configured under `spec.router.doh.certFile/keyFile`).

Optional DoS protections, all applied only at the router (slaves are never rate-limited):

- **Per-source-prefix rate limiting** independently for UDP, TCP, DoH, and DoT (`spec.router.rateLimits`). Over-limit behavior: UDP silent-drop (or TC=1 slip), TCP/DoT close, DoH HTTP 429.
- **CIDR allowlist** (`spec.router.rateLimits.allowlist`) for loopback and trusted internal ranges — matching queries bypass all four limiters. When unset, defaults to all non-globally-routable ranges (loopback, RFC 1918, link-local, CGNAT, IPv6 ULA), assuming the router faces a public IP via `hostPort`.
- **Concurrent-connection caps** for TCP, DoH, and DoT (`spec.router.maxConnections`, default 10 000 per protocol). Over-cap: TCP/DoT close, DoH HTTP 503.

### RFC 2136 Gateway

Optional sidecar that accepts DNS UPDATE messages (RFC 2136) authenticated with TSIG, and translates them into `DNSRecord` CRD create/update/delete operations. Enables external tools (e.g. cert-manager, ACME clients) to manage DNS records without direct Kubernetes API access.

## DNS Records

Records are stored as `DNSRecord` CRDs:

```yaml
apiVersion: xfx1.de/v2
kind: DNSRecord
metadata:
  name: example-a
  namespace: xfx1-dns
spec:
  name: "example.com."
  rrtype: A
  ttl: 300
  payload:
    address: "1.2.3.4"
```

Supported record types: see [internal/rec/rrtype.go](internal/rec/rrtype.go).

DNSSEC records (`DNSKEY`, `RRSIG`, `DS`, `NSEC3`, `NSEC3PARAM`) are generated automatically by the master when signing keys are configured.

## Configuration

All configuration lives in a single `DNSConfig` CRD. Fields are documented in [`internal/crd/crd.go`](internal/crd/crd.go); the `dnsConfig`/`dnsRecord` builders in [`deploy/crds.libsonnet`](deploy/crds.libsonnet) construct the CRs, and [`test/deployment.jsonnet`](test/deployment.jsonnet) is a worked example.

## License

Copyright 2026 the `xfx1-dns` authors.
Licensed under the [GNU Affero General Public License v3.0](LICENSE).
