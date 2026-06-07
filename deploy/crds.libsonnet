{
  crds::
    {
      dnsRecord:
        {
          apiVersion: 'apiextensions.k8s.io/v1',
          kind: 'CustomResourceDefinition',
          metadata:
            { name: 'dnsrecords.xfx1.de' },
          spec:
            {
              group: 'xfx1.de',
              names:
                {
                  kind: 'DNSRecord',
                  plural: 'dnsrecords',
                  singular: 'dnsrecord',
                },
              scope: 'Namespaced',
              versions:
                [
                  {
                    name: 'v2',
                    served: true,
                    storage: true,
                    schema:
                      {
                        openAPIV3Schema:
                          {
                            type: 'object',
                            properties:
                              {
                                spec:
                                  {
                                    type: 'object',
                                    properties:
                                      {
                                        name:
                                          { type: 'string' },
                                        rrtype:
                                          {
                                            type: 'string',
                                            enum: ['A', 'AAAA', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'SRV', 'CAA'],
                                          },
                                        ttl:
                                          { type: 'integer' },
                                        payload:
                                          {
                                            type: 'object',
                                            'x-kubernetes-preserve-unknown-fields': true,
                                          },
                                      },
                                  },
                              },
                          },
                      },
                    additionalPrinterColumns:
                      [
                        {
                          name: 'Name',
                          type: 'string',
                          jsonPath: '.spec.name',
                        },
                        {
                          name: 'Type',
                          type: 'string',
                          jsonPath: '.spec.rrtype',
                        },
                        {
                          name: 'Source',
                          type: 'string',
                          jsonPath: ".metadata.labels['dns\\.xfx1\\.de/source']",
                        },
                      ],
                  },
                ],
            },
        },
      dnsConfig:
        {
          apiVersion: 'apiextensions.k8s.io/v1',
          kind: 'CustomResourceDefinition',
          metadata:
            { name: 'dnsconfigs.xfx1.de' },
          spec:
            {
              group: 'xfx1.de',
              names:
                {
                  kind: 'DNSConfig',
                  plural: 'dnsconfigs',
                  singular: 'dnsconfig',
                },
              scope: 'Namespaced',
              versions:
                [
                  {
                    name: 'v2',
                    served: true,
                    storage: true,
                    schema:
                      {
                        openAPIV3Schema:
                          {
                            type: 'object',
                            properties:
                              {
                                spec:
                                  {
                                    type: 'object',
                                    properties:
                                      {
                                        global:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                zone:
                                                  { type: 'string' },
                                                logLevel:
                                                  {
                                                    type: 'string',
                                                    enum: ['debug', 'info', 'error'],
                                                  },
                                              },
                                          },
                                        master:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                slaveDiscoveryRecord:
                                                  { type: 'string' },
                                                resignInterval:
                                                  { type: 'string' },
                                                maxRecords:
                                                  {
                                                    type: 'integer',
                                                    minimum: 0,
                                                    description:
                                                      |||
                                                        Maximum number of user records accepted per DB rebuild.
                                                        0 uses the default of 100 000.
                                                      |||,
                                                  },
                                              },
                                          },
                                        slave:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                masterAddr:
                                                  { type: 'string' },
                                                pollInterval:
                                                  { type: 'string' },
                                                listenPort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                    description: 'UDP/TCP port to listen on for DNS queries. Default: 5353.',
                                                  },
                                                snapshotLocation:
                                                  {
                                                    type: 'string',
                                                    description: 'Path to snapshot file for DB persistence across restarts. Requires a volume.',
                                                  },
                                              },
                                          },
                                        router:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                slaveDiscoveryRecord:
                                                  { type: 'string' },
                                                forwardTimeout:
                                                  { type: 'string' },
                                                listenPort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                    description: 'UDP/TCP port the router binds inside the container. Default: 5353.',
                                                  },
                                                slavePort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                    description: 'Port to dial on slave IPs. Must match slave.listenPort. Default: 5353.',
                                                  },
                                                dohPort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                    description: 'Port the router binds for DNS-over-HTTPS. Default: 8443.',
                                                  },
                                                dotPort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                    description: 'Port the router binds for DNS-over-TLS. Default: 8853.',
                                                  },
                                                doh:
                                                  {
                                                    type: 'object',
                                                    properties:
                                                      {
                                                        certFile:
                                                          { type: 'string' },
                                                        keyFile:
                                                          { type: 'string' },
                                                      },
                                                  },
                                                rateLimits:
                                                  {
                                                    type: 'object',
                                                    properties:
                                                      {
                                                        local rateLimitConfig =
                                                          {
                                                            type: 'object',
                                                            properties:
                                                              {
                                                                enabled:
                                                                  { type: 'boolean' },
                                                                burstSize:
                                                                  { type: 'integer', minimum: 1 },
                                                                ratePerSec:
                                                                  { type: 'number', minimum: 0 },
                                                                slipRatio:
                                                                  {
                                                                    type: 'integer',
                                                                    minimum: 0,
                                                                    description: 'UDP only: every N-th drop sends TC=1.',
                                                                  },
                                                                maxBuckets:
                                                                  {
                                                                    type: 'integer',
                                                                    minimum: 0,
                                                                    description: 'Cap on tracked source prefixes. 0 uses the default.',
                                                                  },
                                                                maxAge:
                                                                  {
                                                                    type: 'string',
                                                                    description: 'Go duration; how long a bucket is retained. Default 5m.',
                                                                  },
                                                              },
                                                          },
                                                        udp: rateLimitConfig,
                                                        tcp: rateLimitConfig,
                                                        doh: rateLimitConfig,
                                                        dot: rateLimitConfig,
                                                        allowlist:
                                                          {
                                                            type: 'array',
                                                            items:
                                                              { type: 'string' },
                                                            description:
                                                              |||
                                                                CIDR prefixes that bypass rate limiting on all protocols.
                                                                Empty/unset uses defaults (loopback, RFC 1918, link-local, CGNAT, IPv6 ULA).
                                                                Set a non-matching CIDR like "255.255.255.255/32" to disable bypass.
                                                              |||,
                                                          },
                                                      },
                                                  },
                                                maxConnections:
                                                  {
                                                    type: 'object',
                                                    properties:
                                                      {
                                                        tcp:
                                                          {
                                                            type: 'integer',
                                                            minimum: 0,
                                                            description: 'Concurrent client TCP conns. 0 uses the default of 10 000.',
                                                          },
                                                        doh:
                                                          {
                                                            type: 'integer',
                                                            minimum: 0,
                                                            description: 'Concurrent in-flight DoH requests. 0 uses the default of 10 000.',
                                                          },
                                                        dot:
                                                          {
                                                            type: 'integer',
                                                            minimum: 0,
                                                            description: 'Concurrent DoT connections. 0 uses the default of 10 000.',
                                                          },
                                                      },
                                                  },
                                              },
                                          },
                                        dnssec:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                keys:
                                                  {
                                                    type: 'array',
                                                    items:
                                                      {
                                                        type: 'object',
                                                        properties:
                                                          {
                                                            secretRef:
                                                              { type: 'string' },
                                                          },
                                                      },
                                                  },
                                                rrSigValidityWindow:
                                                  { type: 'string' },
                                              },
                                          },
                                        rfc2136:
                                          {
                                            type: 'object',
                                            properties:
                                              {
                                                listenPort:
                                                  {
                                                    type: 'integer',
                                                    minimum: 1,
                                                    maximum: 65535,
                                                  },
                                                tsigSecret:
                                                  { type: 'string' },
                                                tsigName:
                                                  { type: 'string' },
                                              },
                                          },
                                      },
                                  },
                              },
                          },
                      },
                  },
                ],
            },
        },
    },

  dnsRecord::
    {
      new(name, ns):
        {
          apiVersion:
            '%s/%s' % [$.crds.dnsRecord.spec.group, $.crds.dnsRecord.spec.versions[0].name],
          kind: $.crds.dnsRecord.spec.names.kind,
          metadata:
            { name: name, namespace: ns },
        },
      withName(dnsName):
        { spec+: { name: dnsName } },
      withType(rrtype):
        { spec+: { rrtype: rrtype } },
      withTTL(ttl):
        { spec+: { ttl: ttl } },
      withPayload(payload):
        { spec+: { payload: payload } },
    },

  dnsConfig::
    {
      new(name, ns):
        {
          apiVersion:
            '%s/%s' % [$.crds.dnsConfig.spec.group, $.crds.dnsConfig.spec.versions[0].name],
          kind: $.crds.dnsConfig.spec.names.kind,
          metadata:
            { name: name, namespace: ns },
        },
      withGlobal(cfg):
        { spec+: { global+: cfg } },
      withMaster(cfg):
        { spec+: { master+: cfg } },
      withSlave(cfg):
        { spec+: { slave+: cfg } },
      withRouter(cfg):
        { spec+: { router+: cfg } },
      withDNSSEC(cfg):
        { spec+: { dnssec+: cfg } },
      withRFC2136(cfg):
        { spec+: { rfc2136+: cfg } },

      global::
        {
          new():
            {
              spec+:
                {
                  global+:
                    {
                      zone:
                        error 'global.zone must be set',
                    },
                },
            },
          withZone(zone):
            { spec+: { global+: { zone: zone } } },
          withLogLevel(level):
            { spec+: { global+: { logLevel: level } } },
        },

      master::
        {
          new():
            {
              spec+:
                {
                  master+:
                    {
                      slaveDiscoveryRecord:
                        error 'master.slaveDiscoveryRecord must be set',
                    },
                },
            },
          withSlaveDiscoveryRecord(r):
            { spec+: { master+: { slaveDiscoveryRecord: r } } },
          withResignInterval(d):
            { spec+: { master+: { resignInterval: d } } },
          withMaxRecords(n):
            { spec+: { master+: { maxRecords: n } } },
        },

      slave::
        {
          new():
            {
              spec+:
                {
                  slave+:
                    {
                      masterAddr:
                        error 'slave.masterAddr must be set',
                      listenPort: 5353,
                    },
                },
            },
          withMasterAddr(addr):
            { spec+: { slave+: { masterAddr: addr } } },
          withPollInterval(d):
            { spec+: { slave+: { pollInterval: d } } },
          withListenPort(port):
            { spec+: { slave+: { listenPort: port } } },
          withSnapshotLocation(path):
            { spec+: { slave+: { snapshotLocation: path } } },
        },

      router::
        {
          new():
            {
              spec+:
                {
                  router+:
                    {
                      slaveDiscoveryRecord:
                        error 'router.slaveDiscoveryRecord must be set',
                      listenPort: 5353,
                      slavePort: 5353,
                      dohPort: 8443,
                      dotPort: 8853,
                    },
                },
            },
          withSlaveDiscoveryRecord(r):
            { spec+: { router+: { slaveDiscoveryRecord: r } } },
          withForwardTimeout(d):
            { spec+: { router+: { forwardTimeout: d } } },
          withListenPort(port):
            { spec+: { router+: { listenPort: port } } },
          withSlavePort(port):
            { spec+: { router+: { slavePort: port } } },
          withDohPort(port):
            { spec+: { router+: { dohPort: port } } },
          withDotPort(port):
            { spec+: { router+: { dotPort: port } } },
          withDoh(certFile, keyFile):
            {
              spec+:
                {
                  router+:
                    {
                      doh:
                        { certFile: certFile, keyFile: keyFile },
                    },
                },
            },
        },

      dnssec::
        {
          new():
            { spec+: { dnssec+: { rrSigValidityWindow: '168h' } } },
          withKey(secretRef):
            { spec+: { dnssec+: { keys+: [{ secretRef: secretRef }] } } },
          withKeys(keys):
            { spec+: { dnssec+: { keys: keys } } },
          withRRSigValidityWindow(d):
            { spec+: { dnssec+: { rrSigValidityWindow: d } } },
        },

      rfc2136::
        {
          new():
            {
              spec+:
                {
                  rfc2136+:
                    {
                      listenPort: 5053,
                      tsigSecret:
                        error 'rfc2136.tsigSecret must be set',
                      tsigName:
                        error 'rfc2136.tsigName must be set',
                    },
                },
            },
          withListenPort(port):
            { spec+: { rfc2136+: { listenPort: port } } },
          withTsigSecret(secret):
            { spec+: { rfc2136+: { tsigSecret: secret } } },
          withTsigName(name):
            { spec+: { rfc2136+: { tsigName: name } } },
        },

      // rateLimits and maxConnections live here (not under router::) because
      // their per-protocol structure is shared and may be reused independently.
      rateLimits::
        {
          withUDP(cfg):
            { spec+: { router+: { rateLimits+: { udp: cfg } } } },
          withTCP(cfg):
            { spec+: { router+: { rateLimits+: { tcp: cfg } } } },
          withDOH(cfg):
            { spec+: { router+: { rateLimits+: { doh: cfg } } } },
          withDOT(cfg):
            { spec+: { router+: { rateLimits+: { dot: cfg } } } },
          withAllowlist(cidrs):
            { spec+: { router+: { rateLimits+: { allowlist: cidrs } } } },

          protocol::
            {
              new():
                { enabled: false },
              withEnabled(v):
                { enabled: v },
              withBurstSize(n):
                { burstSize: n },
              withRatePerSec(n):
                { ratePerSec: n },
              withSlipRatio(n):
                { slipRatio: n },
              withMaxBuckets(n):
                { maxBuckets: n },
              withMaxAge(d):
                { maxAge: d },
            },
        },

      maxConnections::
        {
          withTCP(n):
            { spec+: { router+: { maxConnections+: { tcp: n } } } },
          withDOH(n):
            { spec+: { router+: { maxConnections+: { doh: n } } } },
          withDOT(n):
            { spec+: { router+: { maxConnections+: { dot: n } } } },
        },
    },
}
