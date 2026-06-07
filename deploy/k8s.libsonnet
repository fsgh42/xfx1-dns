{
  // these share at least these specs: container, probes, env, ports, ...
  local workload =
    {
      new(name, ns):
        {
          apiVersion: 'apps/v1',
          kind: error 'kind must be set',
          metadata:
            { name: name, namespace: ns },
          spec:
            {
              selector:
                { matchLabels: { app: '%s-%s' % [ns, name] } },
              template:
                {
                  metadata:
                    { labels: { app: '%s-%s' % [ns, name] } },
                  spec:
                    { containers: [] },
                },
            },
        },
      withKind(kind):
        { kind: kind },
      withServiceAccount(serviceAccount):
        { spec+: { template+: { spec+: { serviceAccountName: serviceAccount.metadata.name } } } },
      withSecurityContext(secCtx):
        { spec+: { template+: { spec+: { securityContext: secCtx } } } },
      withImagePullSecret(name):
        { spec+: { template+: { spec+: { imagePullSecrets+: [{ name: name }] } } } },
      withAffinity(affinity):
        { spec+: { template+: { spec+: { affinity: affinity } } } },
      withContainer(container):
        { spec+: { template+: { spec+: { containers+: [container] } } } },
      withVolume(volume):
        { spec+: { template+: { spec+: { volumes+: [volume] } } } },
      withNodeAffinity(key, operator):
        self.withAffinity(
        {
          local pref =
            { matchExpressions: [{ key: key, operator: operator }] },
          nodeAffinity:
            {
              preferredDuringSchedulingIgnoredDuringExecution:
                [{ weight: 100, preference: pref }],
            },
        }
        )
    },

  probe::
    {
      new(path, initialDelaySeconds=1, periodSeconds=3, failureThreshold=5):
        {
          httpGet:
            { path: path, port: 'health' },
          initialDelaySeconds: initialDelaySeconds,
          periodSeconds: periodSeconds,
          failureThreshold: failureThreshold,
        },
    },
  container::
    {
      new:
        { name: error 'container.name must be set', image: error 'container.image must be set', ports: [] },
      withImage(image):
        { image: image },
      withName(name):
        { name: name },
      withEnv(env):
        { env+: env },
      withSecurityContext(secCtx):
        { securityContext: secCtx },
      withLivenessProbe(probe):
        { livenessProbe: probe },
      withReadinessProbe(probe):
        { readinessProbe: probe },
      withPort(name, containerPort, protocol, hostPort=null):
        local p = { name: name, containerPort: containerPort, protocol: protocol };
        { ports+: [if hostPort != null then p + { hostPort: hostPort } else p] },
      withVolumeMount(name, mountPath, readOnly=null):
        local vm = { name: name, mountPath: mountPath };
        { volumeMounts+: [if readOnly != null then vm + { readOnly: readOnly } else vm] },
    },
  daemonSet::
    workload
    {
      new(name, ns):
        workload.new(name, ns) +
        workload.withKind('DaemonSet'),
    },
  deployment::
    workload
    {
      new(name, ns):
        workload.new(name, ns) +
        workload.withKind('Deployment'),
    },

  imagePullSecret::
    {
      new(name, ns)::
        $.secret.new(name, ns) +
        $.secret.withType('kubernetes.io/dockerconfigjson') +
        {
          local this = self,
          auths:: {},
          stringData:
            { '.dockerconfigjson': std.manifestJsonEx({ auths: this.auths }, '  ') },
        },
      withAuth(registry, authData):
        { auths+:: { [registry]: { auth: authData } } },
    },
  namespace::
    {
      new(name):
        {
          apiVersion: 'v1',
          kind: 'Namespace',
          metadata:
            { name: name },
        },
      withPriviledged:
        {
          local pl = { 'pod-security.kubernetes.io/enforce': 'privileged' },
          metadata+: { labels+: pl },
        },
    },
  role::
    {
      new(name, ns)::
        {
          apiVersion: 'rbac.authorization.k8s.io/v1',
          kind: 'Role',
          metadata:
            { name: ns, namespace: ns },
          rules: [],
        },
      withRule(apiGroups, resources, verbs)::
        { rules+: [{ apiGroups: apiGroups, resources: resources, verbs: verbs }] },
    },
  roleBinding::
    {
      new(name, ns, role):
        {
          apiVersion: 'rbac.authorization.k8s.io/v1',
          kind: 'RoleBinding',
          metadata:
            { name: ns, namespace: ns },
          subjects: [],
          roleRef:
            { kind: 'Role', name: role.metadata.name, apiGroup: 'rbac.authorization.k8s.io' },
        },
      withSubject(subject):
        { subjects+: [{ kind: subject.kind, name: subject.metadata.name, namespace: subject.metadata.namespace }] },
    },
  secret::
    {
      new(name, ns):
        {
          apiVersion: 'v1',
          kind: 'Secret',
          metadata:
            { name: name, namespace: ns },
        },
      withStringData(data):
        { stringData+: data },
      withType(type):
        { type: type },
    },
  service::
    {
      new(name, ns):
        {
          apiVersion: 'v1',
          kind: 'Service',
          metadata:
            { name: name, namespace: ns },
        },
      withSelector(selector):
        { spec+: { selector+: selector } },
      withClusterIP(ip):
        { spec+: { clusterIP: ip } },
      withPorts(ports):
        { spec+: { ports+: ports } },
    },
  serviceAccount::
    {
      new(name, ns):
        {
          apiVersion: 'v1',
          kind: 'ServiceAccount',
          metadata:
            { name: ns, namespace: ns },
        },
    },

}
