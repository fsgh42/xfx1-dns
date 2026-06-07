// In-cluster one-shot test Job for xfx1-dns.
//
// Usage:
//   jrsonnet -y test/test.jsonnet
//   jrsonnet -y --tla-str endpointMode=external --tla-str tlsInsecure=1 test/test.jsonnet
//
// Parameters:
//   namespace     - target namespace (default: xfx1-dns)
//   imageTag      - image tag to use (default: local)
//   imagePullSecret / registryServer / registryAuth - optional registry auth
//   endpointMode  - "internal" (router ClusterIP svc) or "external" (pod hostIPs)
//   plain         - run plain TCP+UDP record checks (default: 1)
//   dnssec        - run DNSSEC + RRSIG verification checks (default: 1)
//   edns0         - run EDNS(0) compliance checks (default: 1)
//   doh           - run DNS-over-HTTPS checks (default: 1)
//   dot           - run DNS-over-TLS checks (default: 1)
//   tlsInsecure   - skip TLS certificate verification for DoH/DoT (default: 0)
//   dnsPort       - DNS port (default: 53)
//   dohPort       - DoH port (default: 443)
//   dotPort       - DoT port (default: 853)

local ns = 'xfx1-dns';
local imageBase = 'cr.xfx1.de/infrastructure/xfx1-dns';

local podSecCtx = {
  runAsNonRoot: true,
  runAsUser: 65534,
  seccompProfile: { type: 'RuntimeDefault' },
};

local containerSecCtx = {
  allowPrivilegeEscalation: false,
  capabilities: { drop: ['ALL'] },
};

function(
  namespace=ns,
  imageTag='local',
  imagePullSecret='',
  registryServer='',
  registryAuth='',
  endpointMode='internal',
  plain='1',
  dnssec='1',
  edns0='1',
  doh='1',
  dot='1',
  tlsInsecure='0',
  dnsPort='53',
  dohPort='443',
  dotPort='853',
)

  local env = [
    { name: 'NAMESPACE',      value: namespace },
    { name: 'ENDPOINT_MODE',  value: endpointMode },
    { name: 'PLAIN',          value: plain },
    { name: 'DNSSEC',         value: dnssec },
    { name: 'EDNS0',          value: edns0 },
    { name: 'DOH',            value: doh },
    { name: 'DOT',            value: dot },
    { name: 'TLS_INSECURE',   value: tlsInsecure },
    { name: 'DNS_PORT',       value: dnsPort },
    { name: 'DOH_PORT',       value: dohPort },
    { name: 'DOT_PORT',       value: dotPort },
  ];

  local resources = [
    // ── ServiceAccount ────────────────────────────────────────────────────────
    {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: { name: 'xfx1-dns-test', namespace: namespace },
    },

    // ── Role ──────────────────────────────────────────────────────────────────
    {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'Role',
      metadata: { name: 'xfx1-dns-test', namespace: namespace },
      rules: [
        {
          // Read DNSRecord CRDs.
          apiGroups: ['xfx1.de'],
          resources: ['dnsrecords'],
          verbs: ['get', 'list'],
        },
        {
          // Read router TLS secret for DoH/DoT.
          apiGroups: [''],
          resources: ['secrets'],
          verbs: ['get'],
        },
        {
          // List router pods for external endpoint discovery.
          apiGroups: [''],
          resources: ['pods'],
          verbs: ['get', 'list'],
        },
      ],
    },

    // ── RoleBinding ───────────────────────────────────────────────────────────
    {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: { name: 'xfx1-dns-test', namespace: namespace },
      subjects: [{ kind: 'ServiceAccount', name: 'xfx1-dns-test', namespace: namespace }],
      roleRef: {
        kind: 'Role',
        name: 'xfx1-dns-test',
        apiGroup: 'rbac.authorization.k8s.io',
      },
    },

    // ── Job ───────────────────────────────────────────────────────────────────
    {
      apiVersion: 'batch/v1',
      kind: 'Job',
      metadata: { name: 'xfx1-dns-test', namespace: namespace },
      spec: {
        ttlSecondsAfterFinished: 600,
        backoffLimit: 0,
        template: {
          metadata: { labels: { app: 'xfx1-dns-test' } },
          spec: {
            serviceAccountName: 'xfx1-dns-test',
            restartPolicy: 'Never',
            securityContext: podSecCtx,
          }
          + (if imagePullSecret != '' then { imagePullSecrets: [{ name: imagePullSecret }] } else {})
          + {
            containers: [{
              name: 'test',
              image: '%s/test:%s' % [imageBase, imageTag],
              securityContext: containerSecCtx,
              env: env,
            }],
          },
        },
      },
    },
  ]

  + (if imagePullSecret != '' && registryServer != '' && registryAuth != '' then [{
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name: imagePullSecret, namespace: namespace },
    type: 'kubernetes.io/dockerconfigjson',
    stringData: {
      '.dockerconfigjson': std.manifestJsonEx({
        auths: { [registryServer]: { auth: std.stripChars(registryAuth, '"') } },
      }, '  '),
    },
  }] else []);

  resources
