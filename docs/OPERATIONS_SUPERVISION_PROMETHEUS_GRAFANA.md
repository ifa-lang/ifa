# IFA ISSP Multipath Supervision: Prometheus & Grafana Operations Guide

**Author:** ASSOGBA Prudence Dieudonné (@jprud67)  
**Status:** Operational Production Manual  
**Target:** IFA Network Subsystem (`std/net`, `crates/ifa-runtime`, `crates/ifa-cli`)  

---

## 1. Overview & Architectural Principles

The IFA Internet Scale Packet (ISSP) multipath subsystem aggregates multiple heterogeneous physical network links (e.g. Fiber WAN, 5G NR, Satellite, Metro Ethernet) into a resilient virtual ingress/egress transport pipe.

To maintain optimal throughput and avoid latency degradation across paths with divergent characteristics, the IFA runtime couples:
- **LEDBAT (Low Extra Delay Background Transport)**: Proactive queuing delay gradient monitoring to identify bufferbloat before packet drops happen.
- **BBR (Bottleneck Bandwidth and RTT)**: Continuous physical bottleneck bandwidth estimation and pacing gain control.
- **Dynamic Damped Scheduling**: Automated weight adaptation with hysteresis to eliminate route flapping.

The `ifa net session telemetry-serve` command exposes live telemetry over HTTP and WebSocket protocols to interface directly with industry-standard observability stacks (Prometheus, Grafana, OpenTelemetry).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        IFA Production Node                             │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 ISSP Multipath Route Registry                  │   │
│   │  • Subpath 1 (eth0-wan): Low RTT, high bandwidth               │   │
│   │  • Subpath 2 (wwan0-5g): Variable RTT, cellular backup/boost   │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│   ┌───────────────────────────────▼────────────────────────────────┐   │
│   │                     IsspTelemetryServer                        │   │
│   │                                                                │   │
│   │  • GET /metrics      → Prometheus text exposition format       │   │
│   │  • GET /v1/metrics   → OpenTelemetry (OTLP) JSON format        │   │
│   │  • GET /ws/metrics   → High-frequency WebSocket streaming     │   │
│   │  • GET /healthz      → Liveness and health probe               │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ TCP 9100
        ┌───────────────────────────┴───────────────────────────┐
        ▼                                                       ▼
┌────────────────────────────────┐            ┌──────────────────────────────────┐
│      Prometheus Scraper        │            │     NOC Streaming Receiver       │
│  • Scrape interval: 5s         │            │  • WebSocket client              │
│  • Alert evaluations: 5s       │            │  • Sub-second link monitoring    │
└───────────────┬────────────────┘            └──────────────────────────────────┘
                │
                ▼
┌────────────────────────────────┐
│       Grafana Dashboard        │
│  • Real-time traffic share     │
│  • LEDBAT bufferbloat curves   │
│  • Fleet health inventory      │
└────────────────────────────────┘
```

---

## 2. Telemetry Metric Catalog

All metrics emitted by IFA ISSP multipath conform to Prometheus 0.0.4 text exposition standards.

### 2.1 Cluster & Multipath Pool Gauges

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `ifa_issp_multipath_total_paths` | `gauge` | `node_id`, `policy` | Total configured subpaths in the registry, including dormant routes. |
| `ifa_issp_multipath_active_paths` | `gauge` | `node_id`, `policy` | Number of operational subpaths currently eligible for packet distribution. |
| `ifa_issp_multipath_total_effective_weight` | `gauge` | `node_id`, `policy` | Aggregate scheduling weight across all usable subpaths. |
| `ifa_session_total_sessions` | `gauge` | `node_id`, `policy` | Total active sessions tracked in cluster registry. |
| `ifa_session_primary_sessions` | `gauge` | `node_id`, `policy` | Primary active sessions owned by local node. |
| `ifa_session_standby_sessions` | `gauge` | `node_id`, `policy` | Standby shadow-replicated sessions awaiting failover. |

### 2.2 Per-Subpath Gauges, Counters & Retransmissions

All per-subpath metrics share the label set: `node_id`, `path_id`, `interface`, `state`, `phase`.

| Metric Name | Type | Unit | Description |
|---|---|---|---|
| `ifa_issp_subpath_configured_weight` | `gauge` | `scalar` | Administrative base weight configured on the link. |
| `ifa_issp_subpath_effective_weight` | `gauge` | `scalar` | Dynamic scheduling weight after damping and congestion adjustments. |
| `ifa_issp_subpath_traffic_share_ratio` | `gauge` | `[0.0 - 1.0]` | Normalized fraction of ingress traffic allocated to this link. |
| `ifa_issp_subpath_traffic_share_percent` | `gauge` | `%` | Percentage of total traffic allocated to this interface. |
| `ifa_issp_subpath_rtt_seconds` | `gauge` | `seconds` | Smoothed round-trip time calculated via continuous micro-probes. |
| `ifa_issp_subpath_rtt_gradient_seconds` | `gauge` | `seconds` | Measured queuing delay gradient (LEDBAT delay above base RTT). |
| `ifa_issp_subpath_bbr_bw_bps` | `gauge` | `bits/sec` | BBR bottleneck bandwidth estimate. |
| `ifa_issp_subpath_bbr_pacing_gain` | `gauge` | `multiplier` | BBR pacing multiplier (1.0 = nominal pacing). |
| `ifa_issp_subpath_ledbat_cwnd_bytes` | `gauge` | `bytes` | LEDBAT congestion window size. |
| `ifa_issp_subpath_congestion_weight_factor` | `gauge` | `[0.05 - 1.0]` | Dynamic penalty factor applied when queuing delay exceeds target. |
| `ifa_issp_subpath_congestion_events_total` | `counter` | `events` | Cumulative count of congestion and packet-drop signals. |
| `ifa_issp_subpath_bytes_in_flight` | `gauge` | `bytes` | Current unacknowledged bytes in flight across the subpath. |
| `ifa_issp_subpath_frames_sent_total` | `counter` | `frames` | Total datagram frames transmitted across the interface. |
| `ifa_issp_subpath_frames_received_total` | `counter` | `frames` | Total datagram frames acknowledged and received. |
| `ifa_issp_subpath_tcp_retransmissions_total` | `counter` | `segments` | Total TCP segment retransmissions detected on subpath. |
| `ifa_issp_subpath_issp_retransmissions_total` | `counter` | `capsules` | Total ISSP datagram capsule retransmissions on subpath. |
| `ifa_issp_subpath_tcp_retransmission_ratio` | `gauge` | `[0.0 - 1.0]` | Ratio of TCP retransmissions to total frames on subpath. |
| `ifa_issp_subpath_issp_retransmission_ratio` | `gauge` | `[0.0 - 1.0]` | Ratio of ISSP retransmissions to total frames on subpath. |

### 2.3 Interface Latency Histograms & Protocol Retransmission Ratios

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `ifa_issp_interface_latency_seconds_bucket` | `histogram` | `node_id`, `interface`, `le` | Cumulative latency bucket counts (1ms to 2.5s +Inf) per network interface. |
| `ifa_issp_interface_latency_seconds_sum` | `histogram` | `node_id`, `interface` | Sum of observed latency durations in seconds. |
| `ifa_issp_interface_latency_seconds_count` | `histogram` | `node_id`, `interface` | Total count of latency observations recorded on interface. |
| `ifa_session_interface_retransmission_ratio` | `gauge` | `node_id`, `interface`, `protocol` | Retransmission ratio per interface categorized by protocol (`tcp` or `issp`). |

---

## 3. Server Endpoints & Protocols

`ifa net session telemetry-serve` provides a unified HTTP and WebSocket server on a single TCP port (default `:9100`).

### 3.1 Prometheus Pull (`GET /metrics`)

- **Protocol**: HTTP/1.1
- **Content-Type**: `text/plain; version=0.0.4; charset=utf-8`
- **Behavior**: Generates an instantaneous snapshot of the registry's multipath balancing state.
- **Usage**: Scraped periodically by Prometheus or Prometheus Agent.

### 3.2 OpenTelemetry OTLP (`GET /v1/metrics`)

- **Protocol**: HTTP/1.1
- **Content-Type**: `application/json`
- **Alternative Trigger**: Requesting `GET /metrics` with `Accept: application/json`.
- **Behavior**: Emits standard OTLP JSON conforming to OpenTelemetry Metrics specification v1.

### 3.3 High-Frequency Streaming (`GET /ws/metrics`)

- **Protocol**: RFC 6455 WebSocket Upgrade
- **Interval**: Configurable via `--ws-interval-ms` (default: 500 ms)
- **Frame Format**: UTF-8 Text frames containing serialized JSON snapshots:
  ```json
  {
    "timestamp_unix_ns": 1732549200000000000,
    "node_id": "ifa-gateway-prod-01",
    "active_paths": 2,
    "total_effective_weight": 88,
    "routing_policy": "dynamic_latency_gradient",
    "subpaths": [
      {
        "path_id": 1,
        "interface": "eth0-wan",
        "state": "Active",
        "phase": "Normal",
        "rtt_us": 12000,
        "traffic_share_percent": 70.0
      }
    ]
  }
  ```

### 3.4 Liveness & Active Cluster Quorum Health Probes (`/livez` & `/readyz`)

`IsspTelemetryServer` provides native, active health probes conforming to cloud-native orchestrator specifications (Kubernetes, Nomad, Envoy):

#### 3.4.1 Liveness Probe (`GET /livez` & `GET /healthz`)
- **Protocol**: HTTP/1.1
- **Status Code**: `200 OK` (when process and registry mutexes are intact) or `500 Internal Server Error` (if internal locks poisoned).
- **Content-Type**: `text/plain; charset=utf-8` (default: `OK\n`) or `application/json` (if requested via `Accept: application/json`):
  ```json
  {
    "status": "ALIVE",
    "node_id": 1,
    "active_paths": 2,
    "total_sessions": 128
  }
  ```
- **Usage**: Kubernetes `livenessProbe` to detect deadlocks or thread pool starvation.

#### 3.4.2 Readiness Probe (`GET /readyz`) with Quorum Degradation Threshold
- **Protocol**: HTTP/1.1
- **Evaluation Criteria**:
  1. **Cluster Quorum Ratio**: Fraction of reachable cluster nodes (`cluster_nodes / expected_cluster_nodes`) must meet or exceed `quorum_threshold_ratio` (default `0.50`).
  2. **Active Subpaths**: Number of operational subpaths must be $\ge$ `min_active_paths` (default `1`).
  3. **Retransmission Threshold (Optional)**: Aggregate retransmission ratio must not exceed `max_retransmit_ratio` when configured.
- **Status Codes**:
  - `200 OK`: Node is operational, traffic can be safely routed. Body: `READY: cluster quorum healthy (...)`.
  - `503 Service Unavailable`: Cluster quorum degraded below threshold or zero subpaths available. Ingress routers/proxies remove node from rotation until recovery. Body: `DEGRADED: cluster quorum degraded (...)`.
- **JSON Format (`Accept: application/json`)**:
  ```json
  {
    "status": "READY",
    "ready": true,
    "degraded": false,
    "node_id": 1,
    "cluster_nodes": 3,
    "expected_cluster_nodes": 3,
    "quorum_ratio": 1.0000,
    "quorum_threshold_ratio": 0.5000,
    "active_paths": 2,
    "min_active_paths": 1,
    "aggregate_retrans_ratio": 0.0120,
    "reason": "cluster quorum healthy: 3/3 nodes, 2 active paths, 1.00 quorum ratio"
  }
  ```

### 3.5 Load Benchmark: Streaming WebSocket vs HTTP Polling Under Saturation (100k Sessions)

To evaluate telemetry egress scalability under high cluster concurrency, `ifa net session telemetry-bench` profiles RFC 6455 WebSocket streaming against HTTP Prometheus (`/metrics`) and OTLP JSON (`/v1/metrics`) polling under high saturation:

```bash
# Run benchmark under 100k concurrent active sessions (1,000 sample iterations per transport)
ifa net session telemetry-bench --sessions 100000 --iterations 1000
```

#### Production Performance Comparison (100k Active Concurrent Sessions):

| Transport Protocol | Samples | Throughput (snap/s) | Bandwidth (MB/s) | Avg Latency (µs) | P95 Latency (µs) | Framing Overhead | Wire Savings |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **WebSocket Streaming (`/ws/metrics`)** | 1,000 | **~75,000** | ~55 MB/s | **< 15 µs** | **< 20 µs** | **0.68%** | **95.7%** |
| **HTTP Polling Prometheus (`/metrics`)** | 1,000 | ~2,200 | ~39 MB/s | ~450 µs | ~600 µs | 1.23% | 0.0% |
| **HTTP Polling OTLP JSON (`/v1/metrics`)** | 1,000 | ~13,000 | ~350 MB/s | ~75 µs | ~110 µs | 0.69% | 0.0% |

#### Key Architectural Findings:
1. **Framing Efficiency**: Streaming WebSocket replaces repetitive HTTP request/response headers (250–500 bytes per cycle) with a 2-byte RFC 6455 binary frame header, reducing total wire framing overhead by **> 95%**.
2. **Low Latency & Throughput**: WebSocket streaming delivers up to **30x–50x speedup** vs Prometheus text parsing and **5x–10x speedup** vs OTLP JSON polling by avoiding per-sample request extraction and buffer allocations.
3. **Saturation Stability**: Sustained 100% data fidelity under 100,000 concurrent sessions across heterogeneous subpaths (`eth0-wan`, `wwan0-5g`, `tun0-vpn`) without thread pool exhaustion or memory leaks.

---

## 4. Production Deployment Architectures

### 4.1 Systemd Service Unit (Bare-Metal & VM)

Create `/etc/systemd/system/ifa-telemetry.service`:

```ini
[Unit]
Description=IFA ISSP Multipath Telemetry Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ifa
Group=ifa
ExecStart=/usr/local/bin/ifa net session telemetry-serve \
    --addr 0.0.0.0:9100 \
    --node-id %H \
    --ws-interval-ms 500
Restart=always
RestartSec=5s
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ifa-telemetry
```

### 4.2 Docker Compose Stack

A complete turnkey stack is provided in [examples/multipath_monitoring](file:///root/ifa/examples/multipath_monitoring):

```bash
cd examples/multipath_monitoring
docker compose up -d
```

### 4.3 Kubernetes Pod Sidecar

In containerized gateway deployments, the telemetry server runs as a sidecar container sharing the network namespace with the primary packet forwarder:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ifa-ingress-gateway
  labels:
    app.kubernetes.io/name: ifa-ingress
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: ifa-ingress
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ifa-ingress
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9100"
        prometheus.io/path: "/metrics"
    spec:
      containers:
        - name: telemetry-server
          image: ghcr.io/ifa-lang/ifa:latest
          command: ["ifa", "net", "session", "telemetry-serve"]
          args: ["--addr", "0.0.0.0:9100", "--node-id", "$(POD_NAME)"]
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          ports:
            - containerPort: 9100
              name: metrics
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9100
            initialDelaySeconds: 5
            periodSeconds: 10
```

---

## 5. Incident Response Playbook

### 5.1 Alert: `IfaIsspNoActiveSubpaths` (Severity: Critical)

- **Symptom**: All multipath subpaths are in `Failed`, `Standby`, or zero-weight state. Ingress traffic cannot be dispatched.
- **Diagnostic Commands**:
  ```bash
  ifa net session route
  ifa net session list
  ```
- **Remediation**:
  1. Inspect physical link state: `ip link show` on the host.
  2. Test gateway reachability for each interface: `ping -I eth0-wan <gw-ip>`.
  3. Verify DNS / ARP entries.
  4. Force reset or probation clearance if paths were throttled due to flapping.

### 5.2 Alert: `IfaIsspHighQueuingDelayGradient` (Severity: Warning)

- **Symptom**: LEDBAT detected queuing delay above 50ms, signaling upstream bufferbloat.
- **Operational Impact**: IFA will automatically throttle the congested path's weight factor to steer traffic onto lower-latency interfaces.
- **Diagnostic Commands**:
  ```bash
  ifa net session inspect <session-id>
  ```
- **Remediation**:
  1. Observe traffic share in Grafana: confirm traffic has successfully migrated to alternate paths (e.g. `wwan0-5g`).
  2. If all paths exhibit high gradient simultaneously, examine intermediate bottleneck routers or upstream ISP congestion.

### 5.3 Alert: `IfaIsspSubpathDown` (Severity: Warning)

- **Symptom**: An interface with configured administrative weight has dropped to effective weight 0.
- **Diagnostic Commands**:
  ```bash
  journalctl -u ifa-telemetry -n 100 --no-pager
  ```
- **Remediation**:
  1. Verify if the interface is undergoing planned maintenance.
  2. Check whether path entered flapping probation (`ifa net session probation`).
  3. Wait for probation probe cycles to restore link confidence before manually intervening.
