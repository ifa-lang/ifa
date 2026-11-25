# IFA Multipath Telemetry: Prometheus & Grafana Supervision Stack

This directory provides a production-grade monitoring stack for IFA Internet Scale Packet (ISSP) multipath link balancing, dynamic traffic steering, bufferbloat avoidance (LEDBAT), and bottleneck bandwidth tracking (BBR).

---

## 1. Stack Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        IFA Network Ingress Node                        │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │             ifa net session telemetry-serve                   │   │
│   │                                                                │   │
│   │   • GET /metrics       → Prometheus 0.0.4 text export          │   │
│   │   • GET /v1/metrics    → OpenTelemetry (OTLP) JSON format     │   │
│   │   • GET /ws/metrics    → High-frequency WebSocket stream       │   │
│   │   • GET /healthz       → Health & Liveness probe check         │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────┬───────────────────────────────┬───────────────────────┘
                 │ Port 9100                     │ Port 9100
                 ▼                               ▼
┌─────────────────────────────────┐   ┌──────────────────────────────────┐
│           Prometheus            │   │   Streaming Telemetry Clients    │
│   • Scrapes every 5s            │   │   • WebSocket receivers          │
│   • Evaluates alert rules       │   │   • Real-time NOC consoles       │
└────────────────┬────────────────┘   └──────────────────────────────────┘
                 │ Port 9090
                 ▼
┌─────────────────────────────────┐
│        Grafana Dashboard        │
│   • Real-time traffic share     │
│   • LEDBAT bufferbloat gradient │
│   • BBR bottleneck capacity     │
│   • Subpath operational fleet   │
└─────────────────────────────────┘
```

---

## 2. Directory Structure

- `docker-compose.yml` : Complete composition running `ifa-telemetry`, `prometheus`, and `grafana`.
- `Dockerfile` : Production container build for the IFA CLI telemetry runtime.
- `prometheus/prometheus.yml` : Scrape configuration with 5s evaluation frequency.
- `prometheus/alert_rules.yml` : Alert rules (Path degradation, bufferbloat surge, zero paths, BBR collapse).
- `grafana/provisioning/datasources/datasource.yml` : Automatic Prometheus data source registration.
- `grafana/provisioning/dashboards/dashboards.yml` : Automatic dashboard provider configuration.
- `grafana/dashboards/ifa_multipath_dashboard.json` : Production Grafana dashboard definition.

---

## 3. Quickstart: Running with Docker Compose

### Prerequisites

- Docker Engine 24.0+ and Docker Compose v2.20+
- Port 9100 (IFA Telemetry), 9090 (Prometheus), and 3000 (Grafana) available

### Launching the Stack

```bash
docker compose up -d
```

### Checking Services Status

```bash
docker compose ps
```

Verify service logs:

```bash
docker compose logs -f ifa-telemetry
```

---

## 4. Endpoints Verification

### Prometheus Metrics Endpoint

```bash
curl -s http://localhost:9100/metrics | grep ifa_issp
```

Expected output sample:
```
# HELP ifa_issp_multipath_active_paths Number of currently operational multipath subpaths.
# TYPE ifa_issp_multipath_active_paths gauge
ifa_issp_multipath_active_paths{node_id="ifa-gateway-prod-01",policy="dynamic_latency_gradient"} 2
# HELP ifa_issp_subpath_traffic_share_percent Dynamic traffic allocation percentage for this subpath [0.0 - 100.0].
# TYPE ifa_issp_subpath_traffic_share_percent gauge
ifa_issp_subpath_traffic_share_percent{interface="eth0-wan",node_id="ifa-gateway-prod-01",path_id="1",phase="Normal",state="Active"} 70.00
ifa_issp_subpath_traffic_share_percent{interface="wwan0-5g",node_id="ifa-gateway-prod-01",path_id="2",phase="Normal",state="Active"} 30.00
```

### Health & Liveness Probe

```bash
curl -i http://localhost:9100/healthz
```

Expected response: `HTTP/1.1 200 OK` with body `OK`.

### OpenTelemetry OTLP JSON Endpoint

```bash
curl -s http://localhost:9100/v1/metrics | jq .
```

### Real-Time WebSocket Streaming

Using `websocat` or `wscat`:

```bash
websocat ws://localhost:9100/ws/metrics
```

---

## 5. Grafana Dashboard Access

1. Open your browser at `http://localhost:3000`.
2. Anonymous view access is pre-configured. To log in with admin privileges, use credentials:
   - **Username:** `admin`
   - **Password:** `admin`
3. Navigate to **Dashboards** > **IFA Network Operations** > **IFA Multipath Balancing & Ingress Telemetry**.

### Visualized Panels

- **Active Subpaths & Effective Weight**: High-level cluster ingress capacity.
- **Dynamic Traffic Allocation**: Proportional traffic share (%) steered to each physical interface (`eth0-wan`, `wwan0-5g`, etc.).
- **Smoothed RTT**: Continuous path latency tracking in milliseconds.
- **LEDBAT Queuing Delay Gradient**: Bufferbloat and queue build-up detection before packet drops occur.
- **BBR Bottleneck Bandwidth**: Dynamic physical link capacity estimations.
- **Subpath Operational Inventory**: Live status, interface name, path ID, congestion phase, and current weight.

---

## 6. Standalone Execution (Without Docker)

You can run the telemetry server directly from an existing IFA binary alongside local Prometheus:

```bash
ifa net session telemetry-serve \
    --addr 127.0.0.1:9100 \
    --node-id node-primary \
    --ws-interval-ms 500
```
