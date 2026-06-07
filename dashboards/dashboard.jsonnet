// xfx1-dns Grafana dashboard.
//
// Render with:
//   task dashboard:build
//
// Or manually (from within the builder image):
//   jrsonnet -J /vendor/vendor dashboard.jsonnet

local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';

local ts = g.panel.timeSeries;
local stat = g.panel.stat;
local row = g.panel.row;
local prom = g.query.prometheus;
local var = g.dashboard.variable;

// ── helpers ──────────────────────────────────────────────────────────────────

local tsBase(title, query, unit='reqps', legend='{{container}}') =
  ts.new(title)
  + ts.queryOptions.withTargets([
    prom.new('${datasource}', query)
    + prom.withLegendFormat(legend),
  ])
  + ts.standardOptions.withUnit(unit)
  + ts.standardOptions.withMin(0)
  + ts.options.tooltip.withMode('multi')
  + ts.options.tooltip.withSort('desc')
  + ts.options.legend.withDisplayMode('list')
  + ts.options.legend.withCalcs([])
  + ts.fieldConfig.defaults.custom.withFillOpacity(6)
  + ts.fieldConfig.defaults.custom.withShowPoints('never')
  + ts.gridPos.withH(8);

local tsFull(title, query, unit='reqps', legend='{{container}}') =
  tsBase(title, query, unit, legend)
  + ts.gridPos.withW(24);

local tsHalf(title, query, unit='reqps', legend='{{container}}') =
  tsBase(title, query, unit, legend)
  + ts.gridPos.withW(12);

// Single-series time series panel: legend visually hidden via showLegend=false.
// withDisplayMode('hidden') leaves panels empty in this Grafana version;
// list+showLegend=false is what the UI toggle actually writes.
// tooltip.withMode('multi') must be re-applied after legend options: in this
// Grafana version the shared options+: merge path lets legend changes shadow
// the tooltip mode set earlier in tsBase.
local tsHalfSingle(title, query, unit='reqps') =
  tsHalf(title, query, unit)
  + ts.options.legend.withDisplayMode('list')
  + ts.options.legend.withShowLegend(false)
  + ts.options.tooltip.withMode('multi');

// Threshold style for error counters: green at 0, red above.
local errorThresholds =
  ts.standardOptions.thresholds.withMode('absolute')
  + ts.standardOptions.thresholds.withSteps([
    { value: null, color: 'green' },
    { value: 0.001, color: 'red' },
  ])
  + ts.standardOptions.color.withMode('thresholds');

// Pod filter variable for a given component: queries pod names from a metric,
// allows multi-select, defaults to All.
local podVar(name, label, metric) =
  var.query.new(name)
  + var.query.generalOptions.withLabel(label)
  + var.query.queryTypes.withLabelValues('pod', metric)
  + var.query.withDatasource('prometheus', '${datasource}')
  + var.query.selectionOptions.withIncludeAll()
  + var.query.selectionOptions.withMulti();

// ── variables ─────────────────────────────────────────────────────────────────

local variables = [
  var.datasource.new('datasource', 'prometheus')
  + var.datasource.generalOptions.withLabel('Datasource'),

  podVar('router_pod', 'Router', 'router_queries_total'),
  podVar('slave_pod',  'Slave',  'slave_queries_total'),
];

// ── rows & panels ─────────────────────────────────────────────────────────────

local overviewRow =
  row.new('Overview')
  + row.withCollapsed(false)
  + row.withPanels([

    // Total query rate (router).
    tsFull(
      'Queries/sec',
      'sum(rate(router_queries_total{pod=~"$router_pod"}[$__rate_interval]))',
      legend='total',
    )
    + ts.options.legend.withDisplayMode('list')
    + ts.options.legend.withShowLegend(false)
    + ts.options.tooltip.withMode('multi'),

    // Per-RR-type breakdown — router fans out to all slaves, so this reflects
    // the full query mix entering the cluster.
    tsFull(
      'Queries/sec by RR type',
      'sum by (rrtype) (rate(router_queries_total{pod=~"$router_pod"}[$__rate_interval]))',
      legend='{{rrtype}}',
    )
    + ts.options.legend.withPlacement('right')
    + ts.panelOptions.withDescription('Router fan-out: each query is forwarded to all slave pods, so slave totals will be a multiple of this.'),

    // Zone composition by RR type (from master).
    tsFull(
      'Resource records by type',
      'max by (rrtype) (master_rr_count)',
      unit='short',
      legend='{{rrtype}}',
    )
    + ts.options.legend.withDisplayMode('list')
    + ts.options.legend.withCalcs([])
    + ts.options.legend.withPlacement('right'),

    // Per-protocol breakdown — shows the split across UDP, TCP, DoH, and DoT.
    // proto!="" excludes pre-proto series from old deployments that lack the label.
    tsFull(
      'Queries/sec by protocol',
      'sum by (proto) (rate(router_queries_total{proto!="",pod=~"$router_pod"}[$__rate_interval]))',
      legend='{{proto}}',
    )
    + ts.options.legend.withPlacement('right'),

  ]);

local slaveRow =
  row.new('Slave')
  + row.withCollapsed(false)
  + row.withPanels([

    // Response code distribution — rcode label is the human-readable string (NOERROR, NXDOMAIN, …).
    tsFull(
      'Queries/sec by rcode',
      'sum by (rcode) (rate(slave_queries_total{rcode!="",pod=~"$slave_pod"}[$__rate_interval]))',
      legend='{{rcode}}',
    ),

    // Per-type breakdown — supported types only (known wire codes).
    tsFull(
      'Queries/sec by RR type',
      'sum by (rrtype) (rate(slave_queries_total{rrtype!="",supported="true",pod=~"$slave_pod"}[$__rate_interval]))',
      legend='{{rrtype}}',
    )
    + ts.options.legend.withPlacement('right'),

    // Success rate over time: NOERROR / all labelled queries * 100.
    // rcode!="" excludes the unlabelled base series from the denominator.
    tsHalfSingle(
      'Success rate (NOERROR %)',
      |||
        sum(rate(slave_queries_total{rcode="NOERROR",pod=~"$slave_pod"}[$__rate_interval]))
        /
        sum(rate(slave_queries_total{rcode!="",pod=~"$slave_pod"}[$__rate_interval]))
        * 100
      |||,
      unit='percent',
    )
    + ts.standardOptions.thresholds.withMode('absolute')
    + ts.standardOptions.thresholds.withSteps([
      { value: null, color: 'red' },
      { value: 80,   color: 'yellow' },
      { value: 95,   color: 'green' },
    ])
    + ts.standardOptions.color.withMode('thresholds')
    + ts.standardOptions.withMax(100),

    // DB syncs per minute.
    tsHalf(
      'DB syncs/min by method',
      'sum by (method) (rate(slave_db_syncs_total{pod=~"$slave_pod"}[$__rate_interval])) * 60',
      unit='short',
      legend='{{method}}',
    ),

    // Unsupported query types (unrecognised wire codes, AXFR, IXFR).
    // Shows the raw numeric wire value so operators can identify the type.
    tsHalf(
      'Unsupported queries/sec',
      'sum by (rrtype) (rate(slave_queries_total{supported="false",pod=~"$slave_pod"}[$__rate_interval]))',
      legend='{{rrtype}}',
    )
    + ts.options.legend.withPlacement('right'),

  ]);

local masterRow =
  row.new('Master')
  + row.withCollapsed(true)
  + row.withPanels([

    // Rebuild success and errors combined on one panel.
    ts.new('DB rebuilds/min')
    + ts.queryOptions.withTargets([
      prom.new('${datasource}', 'sum(rate(master_db_rebuilds_total[$__rate_interval])) * 60')
      + prom.withLegendFormat('rebuilds'),
      prom.new('${datasource}', 'sum(rate(master_db_rebuild_errors_total[$__rate_interval])) * 60')
      + prom.withLegendFormat('errors'),
    ])
    + ts.standardOptions.withUnit('short')
    + ts.standardOptions.withMin(0)
    + ts.options.tooltip.withMode('multi')
    + ts.options.tooltip.withSort('desc')
    + ts.options.legend.withDisplayMode('list')
    + ts.options.legend.withCalcs([])
    + ts.fieldConfig.defaults.custom.withFillOpacity(6)
    + ts.fieldConfig.defaults.custom.withShowPoints('never')
    + { fieldConfig+: { overrides: [
        ts.fieldOverride.byName.new('errors')
        + ts.fieldOverride.byName.withProperty('color', { mode: 'fixed', fixedColor: 'red' }),
      ] } }
    + ts.gridPos.withH(8)
    + ts.gridPos.withW(12),

    // CRD parsing errors from the k8s watch.
    tsHalfSingle(
      'Watch parse errors/sec',
      'sum(rate(master_watch_parse_errors_total[$__rate_interval]))',
      unit='short',
    )
    + errorThresholds,

    // DNSSEC re-signing — should show a regular spike at the resignInterval.
    tsHalfSingle(
      'DNSSEC resigns/min',
      'sum(rate(master_resigns_total[$__rate_interval])) * 60',
      unit='short',
    ),

  ]);

local rfc2136Row =
  row.new('RFC 2136 Gateway')
  + row.withCollapsed(true)
  + row.withPanels([

    // UPDATE volume by operation type.
    tsFull(
      'UPDATE operations/sec by type',
      'sum by (operation) (rate(rfc2136_updates_total[$__rate_interval]))',
      unit='short',
      legend='{{operation}}',
    ),

    // Errors — green at 0, red above.
    tsHalfSingle(
      'UPDATE errors/sec',
      'sum(rate(rfc2136_update_errors_total[$__rate_interval]))',
      unit='short',
    )
    + errorThresholds,

    // CRD name length overflow.
    tsHalfSingle(
      'CRD name overflow/sec',
      'sum(rate(rfc2136_cr_name_overflow_total[$__rate_interval]))',
      unit='short',
    )
    + errorThresholds,

  ]);

local rateLimitRow =
  row.new('Rate Limiting')
  + row.withCollapsed(true)
  + row.withPanels([

    // Drops and slips — should be zero under normal operation.
    tsHalfSingle(
      'Rate limit drops/sec',
      'sum(rate(router_ratelimit_drops_total{pod=~"$router_pod"}[$__rate_interval]))',
      unit='short',
    )
    + errorThresholds,

    tsHalfSingle(
      'Rate limit slips/sec',
      'sum(rate(router_ratelimit_slips_total{pod=~"$router_pod"}[$__rate_interval]))',
      unit='short',
    )
    + errorThresholds,

    // Current number of tracked client prefixes.
    tsHalfSingle(
      'Active rate limit buckets',
      'max(router_ratelimit_active_buckets{pod=~"$router_pod"})',
      unit='short',
    ),

  ]);

local resourceRow =
  row.new('Pod Resources')
  + row.withCollapsed(true)
  + row.withPanels([

    // CPU cores consumed per pod (sum across all containers in the pod).
    tsHalf(
      'CPU cores per pod',
      'sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="xfx1-dns", container!="POD", container!=""}[$__rate_interval]))',
      unit='short',
      legend='{{pod}}',
    ),

    // Memory working set per pod — what the OOM killer uses.
    tsHalf(
      'Memory per pod',
      'sum by (pod) (container_memory_working_set_bytes{namespace="xfx1-dns", container!="POD", container!=""})',
      unit='bytes',
      legend='{{pod}}',
    ),

    // Network bytes/sec per pod: RX above zero, TX mirrored below.
    ts.new('Network bytes/sec per pod')
    + ts.queryOptions.withTargets([
      prom.new('${datasource}', 'sum by (pod) (rate(container_network_receive_bytes_total{namespace="xfx1-dns"}[$__rate_interval]))')
      + prom.withLegendFormat('rx {{pod}}'),
      prom.new('${datasource}', 'sum by (pod) (rate(container_network_transmit_bytes_total{namespace="xfx1-dns"}[$__rate_interval]))')
      + prom.withLegendFormat('tx {{pod}}'),
    ])
    + ts.standardOptions.withUnit('Bps')
    + ts.options.tooltip.withMode('multi')
    + ts.options.tooltip.withSort('desc')
    + ts.options.legend.withDisplayMode('list')
    + ts.options.legend.withCalcs([])
    + ts.fieldConfig.defaults.custom.withFillOpacity(6)
    + ts.fieldConfig.defaults.custom.withShowPoints('never')
    + ts.gridPos.withH(8)
    + ts.gridPos.withW(12)
    + { fieldConfig+: { overrides+: [
        ts.fieldOverride.byRegexp.new('/^tx /')
        + ts.fieldOverride.byRegexp.withProperty('custom.transform', 'negative-Y'),
      ] } },

    // Network packets/sec per pod: RX above zero, TX mirrored below.
    ts.new('Network packets/sec per pod')
    + ts.queryOptions.withTargets([
      prom.new('${datasource}', 'sum by (pod) (rate(container_network_receive_packets_total{namespace="xfx1-dns"}[$__rate_interval]))')
      + prom.withLegendFormat('rx {{pod}}'),
      prom.new('${datasource}', 'sum by (pod) (rate(container_network_transmit_packets_total{namespace="xfx1-dns"}[$__rate_interval]))')
      + prom.withLegendFormat('tx {{pod}}'),
    ])
    + ts.standardOptions.withUnit('pps')
    + ts.options.tooltip.withMode('multi')
    + ts.options.tooltip.withSort('desc')
    + ts.options.legend.withDisplayMode('list')
    + ts.options.legend.withCalcs([])
    + ts.fieldConfig.defaults.custom.withFillOpacity(6)
    + ts.fieldConfig.defaults.custom.withShowPoints('never')
    + ts.gridPos.withH(8)
    + ts.gridPos.withW(12)
    + { fieldConfig+: { overrides+: [
        ts.fieldOverride.byRegexp.new('/^tx /')
        + ts.fieldOverride.byRegexp.withProperty('custom.transform', 'negative-Y'),
      ] } },

  ]);

// ── dashboard ─────────────────────────────────────────────────────────────────

g.dashboard.new('xfx1-dns')
+ g.dashboard.withUid('xfx1-dns')
+ g.dashboard.withDescription('xfx1-dns authoritative DNS server — master / slave / router / rfc2136')
+ g.dashboard.withTags(['xfx1', 'DNS'])
+ g.dashboard.graphTooltip.withSharedCrosshair()
+ g.dashboard.withRefresh('30s')
+ g.dashboard.time.withFrom('now-3h')
+ g.dashboard.time.withTo('now')
+ g.dashboard.timepicker.withRefreshIntervals(['30s', '1m', '5m', '15m', '30m', '1h'])
+ g.dashboard.withVariables(variables)
+ g.dashboard.withPanels(
  g.util.grid.makeGrid([
    overviewRow,
    slaveRow,
    masterRow,
    rfc2136Row,
    rateLimitRow,
    resourceRow,
  ], panelWidth=12, panelHeight=8)
)
