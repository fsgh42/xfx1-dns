{
  local crds = import '../crds.jsonnet',
  local dashboards = import '../dashboards/dashboard.jsonnet',
  local k8s = import 'k8s.libsonnet',

  config+::
    {
      imagePullSecret: null,
      // {
      //   name: ''
      //   registry: ''
      //   authdata: ''
      // }
      namespace: 'xfx1-dns',
      image:
        {
          base: 'cr.xfx1.de/infrastructure/xfx1-dns',
          tag: error 'config.image.tag must be set',
        },
    },

  manifests::
    {
      crds: crds,
      namespace:
        k8s.namespace.new($.config.namespace) +
        k8s.namespace.withPriviledged,
      rbac:
        {
          local rbac = self,
          serviceAccount:
            k8s.serviceAccount.new($.config.namespace, $.config.namespace),
          role:
            k8s.role.new('xfx1-dns', $.config.namespace) +
            k8s.role.withRule(['xfx1.de'], ['dnsrecords', 'dnsconfigs'], ['get', 'list', 'watch']) +
            k8s.role.withRule(['xfx1.de'], ['dnsrecords'], ['create', 'patch', 'delete']) +
            k8s.role.withRule([''], ['secrets'], ['get']),
          roleBinding:
            k8s.roleBinding.new('xfx1-dns', $.config.namespace, rbac.role) +
            k8s.roleBinding.withSubject(rbac.serviceAccount),
        },
      workloads:
        {
          local depl = k8s.deployment,
          local ctr = k8s.container,
          local ctrSecCtx =
            {
              allowPrivilegeEscalation: false,
              capabilities: { drop: ['ALL'] },
            },
          local ctrEnv =
            [{ name: 'NAMESPACE', valueFrom: { fieldRef: { fieldPath: 'metadata.namespace' } } }],
          local image(name) = '%s/%s:%s' % [$.config.image.base, name, $.config.image.tag],
          local defaultCtr =
            ctr.new +
            ctr.withEnv(ctrEnv) +
            ctr.withLivenessProbe(k8s.probe.new('/health')) +
            ctr.withReadinessProbe(k8s.probe.new('/ready')) +
            ctr.withSecurityContext(ctrSecCtx),
          local podSecCtx =
            {
              runAsNonRoot: true,
              runAsUser: 65534,
              seccompProfile: { type: 'RuntimeDefault' },
            },
          // Pod-level mixins applied to every workload. withSecurityContext and
          // withImagePullSecret are kind-agnostic patches, so the deployment
          // builder is reused for daemonsets too.
          local podHardening =
            depl.withSecurityContext(podSecCtx),
          local pullSecret =
            if $.config.imagePullSecret != null then
              depl.withImagePullSecret($.config.imagePullSecret.name)
            else {},
          master:
            {
              local name = 'master',
              local container =
                defaultCtr +
                ctr.withName(name) +
                ctr.withImage(image(name)) +
                ctr.withReadinessProbe(k8s.probe.new('/ready', failureThreshold=20)) +
                ctr.withPort('api', 8080, 'TCP') +
                ctr.withPort('health', 8081, 'TCP') +
                ctr.withPort('metrics', 9090, 'TCP'),

              workload:
                depl.new(name, $.config.namespace) +
                depl.withContainer(container) +
                depl.withServiceAccount($.manifests.rbac.serviceAccount) +
                podHardening +
                pullSecret,
              service:
                k8s.service.new(name, $.config.namespace) +
                k8s.service.withSelector({ app: '%s-%s' % [$.config.namespace, name] }) +
                k8s.service.withPorts([{ name: 'api', port: 8080, targetPort: 'api' }]),
            },
          slave:
            {
              local name = 'slave',
              local container =
                defaultCtr +
                ctr.withName(name) +
                ctr.withImage(image(name)) +
                ctr.withReadinessProbe(k8s.probe.new('/ready', failureThreshold=20)) +
                ctr.withPort('dns-udp', 5353, 'UDP') +
                ctr.withPort('dns-tcp', 5353, 'TCP') +
                ctr.withPort('api', 8080, 'TCP') +
                ctr.withPort('health', 8081, 'TCP') +
                ctr.withPort('metrics', 9090, 'TCP'),

              workload:
                k8s.daemonSet.new(name, $.config.namespace) +
                k8s.daemonSet.withContainer(container) +
                k8s.daemonSet.withServiceAccount($.manifests.rbac.serviceAccount) +
                k8s.daemonSet.withNodeAffinity('node-role.kubernetes.io/control-plane', 'DoesNotExist') +
                podHardening +
                pullSecret,
              service:
                k8s.service.new(name, $.config.namespace) +
                k8s.service.withSelector({ app: '%s-%s' % [$.config.namespace, name] }) +
                k8s.service.withPorts(
                  [
                    { name: 'dns-udp', port: 5353, protocol: 'UDP', targetPort: 'dns-udp' },
                    { name: 'dns-tcp', port: 5353, protocol: 'TCP', targetPort: 'dns-tcp' },
                    { name: 'api', port: 8080, targetPort: 'api' },
                  ]
                ) +
                k8s.service.withClusterIP('None'),
            },
          router:
            {
              local name = 'router',
              local container =
                defaultCtr +
                ctr.withName(name) +
                ctr.withImage(image(name)) +
                ctr.withPort('dns-udp', 5353, 'UDP', hostPort=53) +
                ctr.withPort('dns-tcp', 5353, 'TCP', hostPort=53) +
                ctr.withPort('doh', 8443, 'TCP', hostPort=443) +
                ctr.withPort('dot', 8853, 'TCP', hostPort=853) +
                ctr.withPort('api', 8080, 'TCP') +
                ctr.withPort('health', 8081, 'TCP') +
                ctr.withPort('metrics', 9090, 'TCP') +
                ctr.withVolumeMount('tls', '/etc/tls', true),

              workload:
                k8s.daemonSet.new(name, $.config.namespace) +
                k8s.daemonSet.withContainer(container) +
                k8s.daemonSet.withServiceAccount($.manifests.rbac.serviceAccount) +
                k8s.daemonSet.withVolume(
                  {
                    name: 'tls',
                    secret:
                      { secretName: '%s-router-tls' % $.config.namespace, optional: true },
                  }
                ) +
                podHardening +
                pullSecret,
              service:
                k8s.service.new(name, $.config.namespace) +
                k8s.service.withSelector({ app: '%s-%s' % [$.config.namespace, name] }) +
                k8s.service.withPorts(
                  [
                    { name: 'dns-udp', port: 53, protocol: 'UDP', targetPort: 'dns-udp' },
                    { name: 'dns-tcp', port: 53, protocol: 'TCP', targetPort: 'dns-tcp' },
                    { name: 'doh', port: 443, protocol: 'TCP', targetPort: 'doh' },
                    { name: 'dot', port: 853, protocol: 'TCP', targetPort: 'dot' },
                  ]
                ),
            },
          rfc2136:
            {
              local name = 'rfc2136',
              local container =
                defaultCtr +
                ctr.withName(name) +
                ctr.withImage(image(name)) +
                ctr.withReadinessProbe(k8s.probe.new('/ready', failureThreshold=10)) +
                ctr.withPort('dns-udp', 5053, 'UDP') +
                ctr.withPort('dns-tcp', 5053, 'TCP') +
                ctr.withPort('health', 8081, 'TCP') +
                ctr.withPort('metrics', 9090, 'TCP'),

              workload:
                depl.new(name, $.config.namespace) +
                depl.withContainer(container) +
                depl.withServiceAccount($.manifests.rbac.serviceAccount) +
                depl.withNodeAffinity('node-role.kubernetes.io/control-plane', 'DoesNotExist') +
                podHardening +
                pullSecret,
              service:
                k8s.service.new(name, $.config.namespace) +
                k8s.service.withSelector({ app: '%s-%s' % [$.config.namespace, name] }) +
                k8s.service.withPorts(
                  [
                    { name: 'dns-udp', port: 5053, protocol: 'UDP', targetPort: 'dns-udp' },
                    { name: 'dns-tcp', port: 5053, protocol: 'TCP', targetPort: 'dns-tcp' },
                  ]
                ),
            },
        },
    },

  local files =
    {
      'crds.yaml':
        $.manifests.crds,
      'namespace.yaml':
        [$.manifests.namespace],
      [if $.config.imagePullSecret != null then 'imagepullsecret.yaml' else null]:
        [
          k8s.imagePullSecret.new($.config.imagePullSecret.name, $.config.namespace) +
          k8s.imagePullSecret.withAuth($.config.imagePullSecret.registry, $.config.imagePullSecret.authData),
        ],
      'rbac.yaml':
        std.objectValues($.manifests.rbac),
    }
    {
      ['%s.yaml' % wl.key]: std.objectValues(wl.value)
      for wl in std.objectKeysValues($.manifests.workloads)
    },
  local rootKustomization =
    {
      apiVersion: 'kustomize.config.k8s.io/v1beta1',
      kind: 'Kustomization',
      resources:
        std.objectFields(files),
    },

  files::
    files
    { 'kustomization.yaml': [rootKustomization] },
}
