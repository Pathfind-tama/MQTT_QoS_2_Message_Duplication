# MQTTX Client QoS 2 Duplicate Delivery Attack Test Report

## Test Overview

| Item | Details |
|------|---------|
| **Target** | MQTTX Client |
| **Client Version** | 1.13.0 |
| **Broker** | EMQX Enterprise (Docker image: emqx-enterprise-docker-sf-amd64.tar.gz) |
| **Broker Version** | 6.1.0 (default configuration, await_rel_timeout = 300s) |
| **Scenario** | QoS 2 message publishing over a TLS-encrypted channel |
| **Conclusion** | ✅ Duplicate delivery successfully triggered |

---

## Environment Setup

The test environment uses the official EMQX Enterprise Docker image provided by EMQ Technologies:

- **Image file**: `emqx-enterprise-docker-sf-amd64.tar.gz`
- **Loaded via**: `docker load -i emqx-enterprise-docker-sf-amd64.tar.gz`
- **Container started with**: Default settings, including the default QoS 2 inflight state timeout (`await_rel_timeout = 300 seconds`)
- **TLS**: Enabled using a self-signed certificate for end-to-end encryption between client and broker

---

## Key Prerequisites

To reliably reproduce the issue, the publisher's total reconnection attempts must span beyond the broker's `await_rel_timeout` window (default: 300 seconds).

During testing, we observed that after a TLS sequence number error causes disconnection, MQTTX automatically performs up to 12 reconnection attempts. If all attempts fail, the client terminates. Therefore, the reconnection interval must be configured such that the cumulative retry duration exceeds 300 seconds.

---

## Attack Workflow

### Phase 1: Trigger TLS Error

The attacker drops the second TLS Application Data record (35 bytes long, carrying the MQTT PUBREC packet) immediately after the TLS handshake completes, while forwarding all other traffic normally. This causes MQTTX to close the SSL connection due to a TLS sequence number mismatch.

### Phase 2: Suppress Reconnection Publishing

MQTTX initiates a new TLS connection and sends an MQTT CONNECT packet immediately after the handshake succeeds. At this point, the attacker must intercept and drop the first TLS Application Data record sent from the client to the broker (any length) to block this connection attempt and prevent any subsequent publish.

### Phase 3: Wait for Timeout and Release

The attacker continues suppressing all reconnection attempts until after the 300-second timeout. Once the timeout has passed, packet dropping is stopped. MQTTX then successfully establishes a connection and sends a PUBLISH (DUP=0, same Packet ID) message. Since EMQX has already cleared the QoS 2 inflight state due to `await_rel_timeout`, it treats this as a new message, resulting in a second delivery to subscribers.

---

## Test Materials

This directory contains all materials required for independent reproduction:

| File | Description |
|------|-------------|
| `Attack Demonstration Video.mp4` | Full screen recording of the attack, including client behavior, proxy actions, and real-time Wireshark capture |
| `emqx.log` | Complete EMQX broker logs during the attack window (from video start to end) |
| `poc.py` | Transparent proxy script implementing the two-stage, time-based packet-dropping logic |
| `mqttx_test.pcapng` | Full Wireshark packet capture of the attack, including TLS and MQTT layers |
| `Video Notes.txt` | Text explanation of key timestamps, actions, and observed behaviors in the video |
| `emqx-enterprise-docker-sf-amd64.tar.gz` | Official EMQX Enterprise Docker image used as the vulnerable broker |
