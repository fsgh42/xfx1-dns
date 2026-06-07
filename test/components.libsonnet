local deploy = import '../deploy/deploy.libsonnet';
local k8s = import '../deploy/k8s.libsonnet';

function(
  zone='example.com.',
  imageTag='local',
  imagePullSecret='',
  registryServer='',
  registryAuth='',
)

  local zonePlain    = std.rstripChars(zone, '.');
  local xfx1Ns       = 'xfx1-dns';
  local pebbleNs     = 'pebble';
  local certmgrNs    = 'cert-manager';
  local extdnsNs     = 'external-dns';
  local monitoringNs   = 'monitoring';
  local registryNs     = 'registry';
  local registryNode   = 'xfx1-dns-test-worker-1';
  local registryAddr   = '10.5.0.3:5000';
  local tsigKey        = 'h5dp/TyejV3OxuopYJfFHmOu2U2yPyCt5eDfOGwg0lc=';
  local slaveDnsSvc  = 'slave-dns.%s.svc.cluster.local' % xfx1Ns;
  local rfc2136Svc   = 'rfc2136.%s.svc.cluster.local' % xfx1Ns;
  local pebbleSvc    = 'pebble.%s.svc.cluster.local' % pebbleNs;

  {
    pebble:
      {
        ['pebble/pebble.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'Namespace',
              metadata:
                {
                  name: pebbleNs,
                  labels:
                    { 'pod-security.kubernetes.io/enforce': 'privileged' },
                },
            },
            {
              apiVersion: 'v1',
              kind: 'ConfigMap',
              metadata:
                { name: 'pebble-config', namespace: pebbleNs },
              data:
                {
                  'pebble.json':
                    std.manifestJsonEx(
                      {
                        pebble:
                          {
                            certificate: '/test/certs/localhost/cert.pem',
                            privateKey: '/test/certs/localhost/key.pem',
                            dnsResolver: '%s:53' % slaveDnsSvc,
                            domainBlocklist: [],
                            externalAccountBindingRequired: false,
                            httpPort: 5002,
                            listenAddress: '0.0.0.0:14000',
                            managementListenAddress: '0.0.0.0:15000',
                            ocspResponderURL: '',
                            retryAfter:
                              { authz: 3, order: 5 },
                            tlsPort: 5001,
                          },
                      },
                      '  '
                    ),
                },
            },
            {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata:
                { name: 'pebble', namespace: pebbleNs },
              spec:
                {
                  replicas: 1,
                  selector:
                    { matchLabels: { app: 'pebble' } },
                  template:
                    {
                      metadata:
                        { labels: { app: 'pebble' } },
                      spec:
                        {
                          containers:
                            [
                              {
                                name: 'pebble',
                                image: 'ghcr.io/letsencrypt/pebble:latest',
                                args:
                                  [
                                    '-config',
                                    '/etc/pebble/pebble.json',
                                    '-dnsserver',
                                    '%s:53' % slaveDnsSvc,
                                  ],
                                env:
                                  [
                                    { name: 'PEBBLE_VA_NOSLEEP', value: '1' },
                                    { name: 'PEBBLE_VA_ALWAYS_VALID', value: '0' },
                                  ],
                                ports:
                                  [
                                    { name: 'acme', containerPort: 14000, protocol: 'TCP' },
                                    { name: 'mgmt', containerPort: 15000, protocol: 'TCP' },
                                  ],
                                readinessProbe:
                                  {
                                    httpGet:
                                      { path: '/dir', port: 'acme', scheme: 'HTTPS' },
                                    initialDelaySeconds: 2,
                                    periodSeconds: 5,
                                    failureThreshold: 6,
                                  },
                                volumeMounts:
                                  [
                                    { name: 'config', mountPath: '/etc/pebble', readOnly: true },
                                  ],
                              },
                            ],
                          volumes:
                            [
                              { name: 'config', configMap: { name: 'pebble-config' } },
                            ],
                        },
                    },
                },
            },
            {
              apiVersion: 'v1',
              kind: 'Service',
              metadata:
                { name: 'pebble', namespace: pebbleNs },
              spec:
                {
                  selector:
                    { app: 'pebble' },
                  ports:
                    [
                      { name: 'acme', port: 443, protocol: 'TCP', targetPort: 'acme' },
                      { name: 'mgmt', port: 15000, protocol: 'TCP', targetPort: 'mgmt' },
                    ],
                },
            },
          ],
      },

    certManager:
      {
        ['certmanager/kustomization.yaml']:
          [
            {
              apiVersion: 'kustomize.config.k8s.io/v1beta1',
              kind: 'Kustomization',
              resources:
                ['cluster-issuer.yaml'],
              helmCharts:
                [
                  {
                    name: 'cert-manager',
                    repo: 'oci://quay.io/jetstack/charts',
                    releaseName: 'cert-manager',
                    version: 'v1.20.0',
                    namespace: certmgrNs,
                    includeCRDs: true,
                    valuesFile: 'values.yaml',
                  },
                ],
            },
          ],
        ['certmanager/values.yaml']:
          [
            {
              crds:
                { enabled: true },
              prometheus:
                { enabled: false },
              extraArgs:
                [
                  '--dns01-recursive-nameservers=%s:53' % slaveDnsSvc,
                  '--dns01-recursive-nameservers-only',
                ],
            },
          ],
        ['certmanager/cluster-issuer.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'Namespace',
              metadata:
                {
                  name: certmgrNs,
                  labels:
                    { 'pod-security.kubernetes.io/enforce': 'baseline' },
                },
            },
            {
              apiVersion: 'cert-manager.io/v1',
              kind: 'Certificate',
              metadata:
                { name: 'wildcard', namespace: certmgrNs },
              spec:
                {
                  secretName: 'wildcard-tls',
                  issuerRef:
                    { name: 'pebble', kind: 'ClusterIssuer' },
                  dnsNames:
                    ['*.%s' % zonePlain, zonePlain],
                },
            },
            {
              apiVersion: 'v1',
              kind: 'Secret',
              metadata:
                { name: 'rfc2136-tsig-key', namespace: certmgrNs },
              type: 'Opaque',
              stringData:
                { tsigKey: tsigKey },
            },
            {
              apiVersion: 'cert-manager.io/v1',
              kind: 'ClusterIssuer',
              metadata:
                { name: 'pebble' },
              spec:
                {
                  acme:
                    {
                      server: 'https://%s:443/dir' % pebbleSvc,
                      skipTLSVerify: true,
                      email: 'test@%s' % zonePlain,
                      privateKeySecretRef:
                        { name: 'pebble-issuer-key' },
                      solvers:
                        [
                          {
                            dns01:
                              {
                                rfc2136:
                                  {
                                    nameserver: '%s:5053' % rfc2136Svc,
                                    tsigKeyName: 'acme-key.',
                                    tsigAlgorithm: 'HMACSHA256',
                                    tsigSecretSecretRef:
                                      {
                                        name: 'rfc2136-tsig-key',
                                        key: 'tsigKey',
                                      },
                                  },
                              },
                          },
                        ],
                    },
                },
            },
          ],
      },

    externalDNS:
      local commonValues =
        {
          rbac:
            { create: true },
          provider:
            { name: 'rfc2136' },
          policy: 'upsert-only',
          interval: '30s',
          logLevel: 'debug',
          logFormat: 'json',
          extraArgs:
            [
              '--rfc2136-host=' + rfc2136Svc,
              '--rfc2136-port=5053',
              '--rfc2136-zone=' + zonePlain,
              '--rfc2136-tsig-keyname=acme-key.',
              '--rfc2136-tsig-secret=' + tsigKey,
              '--rfc2136-tsig-secret-alg=hmac-sha256',
            ],
          metrics:
            { enabled: false },
        };
      local chart(releaseName, valuesFile, includeCRDs=false) =
        {
          name: 'external-dns',
          repo: 'https://kubernetes-sigs.github.io/external-dns',
          releaseName: releaseName,
          version: 'v1.20.0',
          namespace: extdnsNs,
          includeCRDs: includeCRDs,
          valuesFile: valuesFile,
        };
      {
        ['external-dns/kustomization.yaml']:
          [
            {
              apiVersion: 'kustomize.config.k8s.io/v1beta1',
              kind: 'Kustomization',
              resources:
                ['namespace.yaml'],
              helmCharts:
                [
                  chart( 'external-dns-nodes', 'values-nodes.yaml', includeCRDs=true ),
                  chart( 'external-dns-services', 'values-services.yaml' ),
                ],
            },
          ],
        ['external-dns/namespace.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'Namespace',
              metadata:
                {
                  name: extdnsNs,
                  labels:
                    { 'pod-security.kubernetes.io/enforce': 'baseline' },
                },
            },
          ],
        ['external-dns/values-nodes.yaml']:
          [
            commonValues
            {
              sources:
                ['node'],
              extraArgs+:
                ['--fqdn-template={{"{{"}}' + '.Name}}.' + zonePlain],
            },
          ],
        ['external-dns/values-services.yaml']:
          [
            commonValues
            { sources: ['service'] },
          ],
      },

    monitoring:
      {
        ['monitoring/kustomization.yaml']:
          [
            {
              apiVersion: 'kustomize.config.k8s.io/v1beta1',
              kind: 'Kustomization',
              resources:
                [
                  'namespace.yaml',
                  'dashboard-configmap.yaml',
                ],
              helmCharts:
                [
                  {
                    name: 'victoria-metrics-k8s-stack',
                    repo: 'https://victoriametrics.github.io/helm-charts',
                    releaseName: 'victoria-metrics-k8s-stack',
                    version: '0.63.5',
                    namespace: monitoringNs,
                    includeCRDs: true,
                    valuesFile: 'vm-values.yaml',
                  },
                ],
            },
          ],
        ['monitoring/namespace.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'Namespace',
              metadata:
                {
                  name: monitoringNs,
                  labels:
                    {
                      'pod-security.kubernetes.io/enforce': 'privileged',
                      'pod-security.kubernetes.io/enforce-version': 'latest',
                    },
                },
            },
          ],
        ['monitoring/dashboard-configmap.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'ConfigMap',
              metadata:
                {
                  name: 'xfx1-dns-dashboard',
                  namespace: monitoringNs,
                  labels:
                    { grafana_dashboard: '1' },
                },
              data:
                {
                  'xfx1-dns.json':
                    importstr '../deploy/dashboard.json',
                },
            },
          ],
        ['monitoring/vm-values.yaml']:
          [
            {
              global:
                {
                  clusterLabel: 'xfx1_dns_test',
                  cluster:
                    { dnsDomain: 'cluster.local.' },
                },

              'victoria-metrics-operator':
                {
                  enabled: true,
                  fullnameOverride: 'vm-operator',
                  admissionWebhooks:
                    { policy: 'Ignore' },
                },

              defaultDashboards:
                { enabled: true, defaultTimezone: 'utc' },

              vmsingle:
                {
                  enabled: true,
                  spec:
                    {
                      port: '8428',
                      retentionPeriod: '7d',
                      replicaCount: 1,
                      storageDataPath: '/var/lib/victoria-metrics-data',
                      volumes:
                        [
                          { name: 'vm-data', emptyDir: {} },
                        ],
                      volumeMounts:
                        [
                          {
                            name: 'vm-data',
                            mountPath: '/var/lib/victoria-metrics-data',
                          },
                        ],
                    },
                  ingress:
                    { enabled: false },
                },

              vmagent:
                {
                  enabled: true,
                  spec:
                    { extraArgs: { enableTCP6: 'true' } },
                  ingress:
                    { enabled: false },
                },

              grafana:
                {
                  enabled: true,
                  ingress:
                    { enabled: false },
                  vmScrape:
                    { enabled: true },
                  plugins: [],
                  persistence:
                    { enabled: false },
                  adminUser: 'admin',
                  adminPassword: 'admin',
                  testFramework:
                    { enabled: false },
                  service:
                    {
                      annotations:
                        {
                          'external-dns.alpha.kubernetes.io/internal-hostname':
                            'grafana.%s.' % zonePlain,
                        },
                    },
                  sidecar:
                    {
                      dashboards:
                        {
                          enabled: true,
                          label: 'grafana_dashboard',
                          labelValue: '1',
                          searchNamespace: monitoringNs,
                        },
                    },
                },

              alertmanager:               { enabled: false },
              vmalert:                    { enabled: false },
              vmauth:                     { enabled: false },
              'prometheus-node-exporter': { enabled: false },
              'kube-state-metrics':       { enabled: false },
              kubelet:                    { enabled: false },
              kubeApiServer:              { enabled: false },
              kubeControllerManager:      { enabled: false },
              kubeDns:                    { enabled: false },
              coreDns:                    { enabled: false },
              kubeEtcd:                   { enabled: false },
              kubeScheduler:              { enabled: false },
              kubeProxy:                  { enabled: false },

              extraObjects:
                [
                  {
                    apiVersion: 'operator.victoriametrics.com/v1beta1',
                    kind: 'VMPodScrape',
                    metadata:
                      { name: 'xfx1-dns', namespace: monitoringNs },
                    spec:
                      {
                        namespaceSelector:
                          { matchNames: [xfx1Ns] },
                        selector:
                          {
                            matchExpressions:
                              [
                                {
                                  key: 'app',
                                  operator: 'In',
                                  values:
                                    [
                                      '%s-master' % xfx1Ns,
                                      '%s-slave' % xfx1Ns,
                                      '%s-router' % xfx1Ns,
                                      '%s-rfc2136' % xfx1Ns,
                                    ],
                                },
                              ],
                          },
                        podMetricsEndpoints:
                          [{ port: 'metrics' }],
                      },
                  },
                ],
            },
          ],
      },

    xfx1dns:
      local pullSecret =
        if imagePullSecret != '' then
          { name: imagePullSecret, registry: registryServer, authData: registryAuth }
        else null;
      local d =
        deploy
        {
          config+:
            {
              image+:
                { tag: imageTag },
              imagePullSecret: pullSecret,
            },
        };
      local extra =
        {
          'slave-dns-svc.yaml':
            [
              k8s.service.new('slave-dns', xfx1Ns)
              + k8s.service.withSelector({ app: '%s-slave' % xfx1Ns })
              + k8s.service.withPorts(
                [
                  { name: 'dns-udp', port: 53, protocol: 'UDP', targetPort: 'dns-udp' },
                  { name: 'dns-tcp', port: 53, protocol: 'TCP', targetPort: 'dns-tcp' },
                ]
              ),
            ],
        };
      local xfxFiles =
        d.files
        + extra
        + {
            'kustomization.yaml':
              [
                d.files['kustomization.yaml'][0]
                { resources+: std.objectFields(extra) },
              ],
          };
      { ['%s/%s' % [xfx1Ns, k]]: xfxFiles[k] for k in std.objectFields(xfxFiles) },

    registry:
      {
        ['registry/registry.yaml']:
          [
            {
              apiVersion: 'v1',
              kind: 'Namespace',
              metadata:
                {
                  name: registryNs,
                  labels:
                    { 'pod-security.kubernetes.io/enforce': 'privileged' },
                },
            },
            {
              apiVersion: 'apps/v1',
              kind: 'Deployment',
              metadata:
                { name: 'registry', namespace: registryNs },
              spec:
                {
                  replicas: 1,
                  selector:
                    { matchLabels: { app: 'registry' } },
                  template:
                    {
                      metadata:
                        { labels: { app: 'registry' } },
                      spec:
                        {
                          nodeSelector:
                            { 'kubernetes.io/hostname': registryNode },
                          containers:
                            [
                              {
                                name: 'registry',
                                image: 'registry:2',
                                ports:
                                  [
                                    {
                                      name: 'registry',
                                      containerPort: 5000,
                                      protocol: 'TCP',
                                      hostPort: 5000,
                                    },
                                  ],
                                volumeMounts:
                                  [
                                    { name: 'data', mountPath: '/var/lib/registry' },
                                  ],
                              },
                            ],
                          volumes:
                            [
                              { name: 'data', emptyDir: {} },
                            ],
                        },
                    },
                },
            },
          ],
      },

    rootKustomization:
      {
        'kustomization.yaml':
          [
            {
              apiVersion: 'kustomize.config.k8s.io/v1beta1',
              kind: 'Kustomization',
              resources:
                [
                  '%s/' % xfx1Ns,
                  'pebble/pebble.yaml',
                  'certmanager/',
                  'external-dns/',
                  'monitoring/',
                  'registry/registry.yaml',
                ],
            },
          ],
      },
  }
