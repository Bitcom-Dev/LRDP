# LRDP Server Logic & Architecture

This document outlines the design for the **Lightweight Registration and Data Protocol (LRDP)** server.

## 1. High-Level Overview

The server's purpose is to autonomously register new devices, ingest high-frequency telemetry data, and provide a mechanism to send commands back to specific devices. The architecture prioritizes performance, low overhead, and concurrency.

## 2. Core Components & Port Strategy

The server will listen on two dedicated ports, each with a distinct role and protocol.

### Port 1: Registration (e.g., `65000/TCP`)
- **Protocol:** **TCP**
- **Reasoning:** Registration is a critical, one-time event. We need the reliability and guaranteed delivery of TCP to ensure the device receives its unique ID and the server confirms the registration.
- **Function:** Handles the initial handshake with new, unregistered devices.

### Port 2: Data & Commands (e.g., `65001/UDP`)
- **Protocol:** **UDP**
- **Reasoning:** Telemetry data (like sensor readings) is often high-volume and time-sensitive. The low overhead of UDP is perfect. Losing a single packet is usually acceptable. This port will also handle heartbeats and downlink commands.
- **Function:** Receives data dumps, heartbeats, and sends command packets back to the devices.
