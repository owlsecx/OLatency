# 🦉 OLatency

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Network%20/%20DNS-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OLatency** — Latency + Jitter Monitor ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OLatency — Latency + Jitter Monitor. Latency + Jitter Monitor (TCP RTT / DNS) Measure round-trip latency with the TCP handshake, DNS resolution latency, and compare two targets head-to-head. Live sparkline, jitter (mean successive difference), mdev, standard deviation and loss — all from the standard library.

---

## ✨ Features

- Monitor latency and jitter toward configured targets
- Summarize loss, RTT distribution and stability signals
- Useful for link quality checks during assessments
- CLI reporting suitable for continuous sampling
- Clear graded posture of network responsiveness
- Export time-series friendly summaries

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OLatency OLatency.go
./OLatency --help
./OLatency --target 1.1.1.1 --count 20
./OLatency --target example.com --format json
./OLatency --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
