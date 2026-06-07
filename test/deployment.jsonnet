local components = import 'components.libsonnet';
local crds = import '../deploy/crds.libsonnet';

function(
  zone='example.com.',
  ns1ip='1.2.3.4',
  imageTag='local',
  imagePullSecret='',
  registryServer='',
  registryAuth='',
)

  local c =
    components(
      zone=zone,
      imageTag=imageTag,
      imagePullSecret=imagePullSecret,
      registryServer=registryServer,
      registryAuth=registryAuth,
    );
  local xfx1Ns    = 'xfx1-dns';
  local zonePlain = std.rstripChars(zone, '.');
  local ns1       = 'ns1.%s.' % zonePlain;
  local slaveSvc  = 'slave.%s.svc.cluster.local.' % xfx1Ns;
  local tsigKey   = 'h5dp/TyejV3OxuopYJfFHmOu2U2yPyCt5eDfOGwg0lc=';

  local record(dnsName, rrtype, payload) =
    local k8sName =
      '%s-%s' % [
        std.strReplace(
          std.strReplace(std.rstripChars(dnsName, '.'), '.', '-'),
          '@',
          'apex'
        ),
        std.asciiLower(rrtype),
      ];
    crds.dnsRecord.new(k8sName, xfx1Ns)
    + crds.dnsRecord.withName(dnsName)
    + crds.dnsRecord.withType(rrtype)
    + crds.dnsRecord.withPayload(payload);

  local config =
    [
      crds.dnsConfig.new(xfx1Ns, xfx1Ns)
      + crds.dnsConfig.global.new()
      + crds.dnsConfig.global.withZone(zone)
      + crds.dnsConfig.global.withLogLevel('debug')
      + crds.dnsConfig.master.new()
      + crds.dnsConfig.master.withSlaveDiscoveryRecord(slaveSvc)
      + crds.dnsConfig.master.withResignInterval('5m')
      + crds.dnsConfig.slave.new()
      + crds.dnsConfig.slave.withMasterAddr(
          'master.%s.svc.cluster.local.:8080' % xfx1Ns
        )
      + crds.dnsConfig.slave.withPollInterval('60s')
      + crds.dnsConfig.router.new()
      + crds.dnsConfig.router.withSlaveDiscoveryRecord(slaveSvc)
      + crds.dnsConfig.router.withForwardTimeout('2s')
      + crds.dnsConfig.router.withDoh('/etc/tls/tls.crt', '/etc/tls/tls.key')
      + crds.dnsConfig.dnssec.new()
      + crds.dnsConfig.dnssec.withKey('%s-zsk' % xfx1Ns)
      + crds.dnsConfig.dnssec.withKey('%s-ksk' % xfx1Ns)
      + crds.dnsConfig.rfc2136.new()
      + crds.dnsConfig.rfc2136.withTsigSecret('rfc2136-tsig-key')
      + crds.dnsConfig.rfc2136.withTsigName('acme-key.'),

      {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata:
          { name: 'rfc2136-tsig-key', namespace: xfx1Ns },
        type: 'Opaque',
        stringData:
          { tsigKey: tsigKey },
      },
      {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata:
          { name: '%s-zsk' % xfx1Ns, namespace: xfx1Ns },
        type: 'Opaque',
        stringData:
          {
            keyType: 'zsk',
            privateKey: |||
              Private-key-format: v1.2
              Algorithm: 15 (ED25519)
              PrivateKey: zjmVqW28A+NPtldGt8Pb0UB/IVtNOzIw+x53LbPEw2s=
            |||,
          },
      },
      {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata:
          { name: '%s-ksk' % xfx1Ns, namespace: xfx1Ns },
        type: 'Opaque',
        stringData:
          {
            keyType: 'ksk',
            privateKey: |||
              Private-key-format: v1.2
              Algorithm: 15 (ED25519)
              PrivateKey: MJwcO6EDShqssrSvTN/ikoBziaHUVEVShyTRdGWsYdg=
            |||,
          },
      },
      {
        apiVersion: 'v1',
        kind: 'Secret',
        metadata:
          { name: '%s-router-tls' % xfx1Ns, namespace: xfx1Ns },
        type: 'kubernetes.io/tls',
        stringData:
          {
            'tls.crt': |||
              -----BEGIN CERTIFICATE-----
              MIIBqzCCAVGgAwIBAgIUTsRGq3fwCUycornVasFecL/955gwCgYIKoZIzj0EAwIw
              GjEYMBYGA1UEAwwPbnMxLmV4YW1wbGUuY29tMB4XDTI2MDMyNDA4MDgxMloXDTI4
              MDYyNjA4MDgxMlowGjEYMBYGA1UEAwwPbnMxLmV4YW1wbGUuY29tMFkwEwYHKoZI
              zj0CAQYIKoZIzj0DAQcDQgAES+EsgDuNLwo0JOIzQywSZKKW5533kYADGqxCvjpK
              0zUzZ5v0kr5Flc/k9YaiGOpQH1uKBbGbD6ZYwa1RzLdW46N1MHMwHQYDVR0OBBYE
              FHQiqLr/JoKy2Bu7mnG8dRMOUra4MB8GA1UdIwQYMBaAFHQiqLr/JoKy2Bu7mnG8
              dRMOUra4MA8GA1UdEwEB/wQFMAMBAf8wIAYDVR0RBBkwF4IPbnMxLmV4YW1wbGUu
              Y29thwQBAgMEMAoGCCqGSM49BAMCA0gAMEUCIQDpTowY9C9Ol+D8BtkHNH8wQ9N6
              gFaNcfC1tAi3aG9vLQIgB5reUeDEX1trQ3Nj157KKOb83kEhmiJO0z6MxIQ8m64=
              -----END CERTIFICATE-----
            |||,
            'tls.key': |||
              -----BEGIN PRIVATE KEY-----
              MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbSRePI1VJND5U3c1
              dlN0cVfKPWDZRQDGKrUvFYKIlKChRANCAARL4SyAO40vCjQk4jNDLBJkopbnnfeR
              gAMarEK+OkrTNTNnm/SSvkWVz+T1hqIY6lAfW4oFsZsPpljBrVHMt1bj
              -----END PRIVATE KEY-----
            |||,
          },
      },
    ];

  local records =
    [
      record(zone, 'SOA',
        {
          mname: ns1,
          rname: 'hostmaster.%s.' % zonePlain,
          refresh: 3600,
          retry: 900,
          expire: 604800,
          minimum: 300,
        }
      ),
      record(zone, 'NS',   { nsdname: ns1 }),
      record(ns1,  'A',    { address: ns1ip }),
      record(ns1,  'AAAA', { address: '2001:db8::1' }),
      record('www.%s.' % zonePlain, 'CNAME', { cname: ns1 }),
      record(zone, 'MX',  { preference: 10, exchange: ns1 }),
      record(zone, 'TXT', { txtdata: 'v=spf1 mx -all' }),
      record('4.3.2.1.in-addr.arpa.', 'PTR', { ptrdname: ns1 }),

      // wildcard: record() produces invalid k8s names for '*'
      crds.dnsRecord.new('wildcard-catchall-a', xfx1Ns)
      + crds.dnsRecord.withName('*.catchall.%s.' % zonePlain)
      + crds.dnsRecord.withType('A')
      + crds.dnsRecord.withPayload({ address: '10.99.0.1' }),

      crds.dnsRecord.new('wildcard-catchall-aaaa', xfx1Ns)
      + crds.dnsRecord.withName('*.catchall.%s.' % zonePlain)
      + crds.dnsRecord.withType('AAAA')
      + crds.dnsRecord.withPayload({ address: '2001:db8::99' }),

      // CAA: same name+zone, different tag — explicit k8s names to avoid collision
      crds.dnsRecord.new('%s-caa-issue' % std.strReplace(zonePlain, '.', '-'), xfx1Ns)
      + crds.dnsRecord.withName(zone)
      + crds.dnsRecord.withType('CAA')
      + crds.dnsRecord.withPayload({ flags: 0, tag: 'issue', value: 'letsencrypt.org' }),

      crds.dnsRecord.new('%s-caa-issuewild' % std.strReplace(zonePlain, '.', '-'), xfx1Ns)
      + crds.dnsRecord.withName(zone)
      + crds.dnsRecord.withType('CAA')
      + crds.dnsRecord.withPayload({ flags: 0, tag: 'issuewild', value: ';' }),

      crds.dnsRecord.new('https-tcp-srv', xfx1Ns)
      + crds.dnsRecord.withName('_https._tcp.%s.' % zonePlain)
      + crds.dnsRecord.withType('SRV')
      + crds.dnsRecord.withPayload({ priority: 10, weight: 20, port: 443, target: ns1 }),
    ];

  c.pebble
  + c.certManager
  + c.externalDNS
  + c.registry
  + c.monitoring
  + c.xfx1dns
  + {
      'xfx1-dns/dnsconfig.yaml': config,
      'xfx1-dns/records.yaml': records,
      'xfx1-dns/kustomization.yaml':
        [
          c.xfx1dns['xfx1-dns/kustomization.yaml'][0]
          { resources+: ['dnsconfig.yaml', 'records.yaml'] },
        ],
    }
  + c.rootKustomization
