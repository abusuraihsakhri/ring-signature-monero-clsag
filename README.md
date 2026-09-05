# Ring Signature Monero CLSAG

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Ring Signature Monero CLSAG** is an analytical and computational platform implementing Monero CLSAG (Compact Linkable Ring Signature) verification and key-image double-spending detection. It provides a multi-agent evaluation engine that processes task payloads through specialized workers to produce consensus dossiers with cryptographic audit trails.

---

## ⚙️ Key Capabilities & Algorithmic Modules

- **Multi-Agent Evaluation Engine**: Three specialized workers (InvariantQC, SafetyEscalation, ProtocolConformance) evaluate task payloads against configurable thresholds.
- **Cryptographic Audit Trail**: HMAC-SHA256 chained, tamper-evident logging for every evaluation and state transition.
- **PHI Outbound Guard**: Regex-based detection and redaction of protected health information (SSNs, MRNs, phone numbers, emails).
- **FastAPI REST API**: OpenAPI-compatible REST endpoints for audit processing and system metrics.
- **CLI Interface**: Command-line tools for single-task evaluation, batch CSV processing, and interactive chat.
- **Prometheus Metrics**: Operational metrics exporter for monitoring system health and throughput.

---

## 💻 Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/ring-signature-monero-clsag.git
cd ring-signature-monero-clsag

# Install dependencies
pip install fastapi uvicorn pydantic pytest

# Optional: Set audit secret key for persistent signatures
export AUDIT_SECRET_KEY="your-secret-key-here"
```

---

## 🚀 CLI Quickstart & Usage

### 1. Single Task Evaluation
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

### 2. Interactive Chat
```bash
python cli.py chat "What is the system status?"
```

### 3. Batch CSV Processing
```bash
python cli.py batch -i sample.csv -o results.csv
```

### 4. Verify Audit Trail Integrity
```bash
python cli.py verify-audit
```

### 5. Launch REST API Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

### Parameter Reference
- `--task-id`: Unique task identifier (required, non-empty)
- `--target`: Target identifier (required, non-empty)
- `--primary`: Primary metric value (float, must be finite)
- `--secondary`: Secondary metric value (float, must be finite)
- `--critical`: Flag for critical escalation (boolean)
- `--status`: Status descriptor (e.g., NOMINAL, DISCORDANT_ANOMALY)

---

## 🛡️ Security Architecture

* **Zero-PHI Outbound Interceptor:** Active regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers from audit logs.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs with integrity verification.
* **Input Validation:** Pydantic validators reject NaN, infinite, and empty identifier values.
* **Configurable Secret Key:** Audit signing key sourced from `AUDIT_SECRET_KEY` environment variable (generates ephemeral key with warning if unset).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py 1000
```

---

## 🐳 Container Deployment

```bash
# Build and run with Docker
docker build -t ring-signature-monero-clsag .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secret ring-signature-monero-clsag

# Or use docker-compose
AUDIT_SECRET_KEY=your-secret docker-compose up
```

---

## 📁 Project Structure

```
ring-signature-monero-clsag/
├── agents/                  # Core multi-agent evaluation engine
│   ├── api.py              # FastAPI REST endpoints
│   ├── base.py             # Security, PHI guard, audit trail
│   ├── models.py           # Pydantic data models with validation
│   ├── supervisor.py       # Orchestrator coordinating workers
│   ├── workers.py          # Specialized evaluation workers
│   ├── metrics.py          # Prometheus metrics exporter
│   ├── learning.py         # Bayesian calibration engine
│   └── streamer.py         # WebSocket telemetry broadcaster
├── ring_clsag_sign/        # CLSAG-specific signature module
│   ├── agents.py           # Ring signature coordinator & agents
│   ├── engine.py           # Core algorithmic engine
│   ├── models.py           # Frontier payload definitions
│   ├── cli.py              # CLI for ring signature module
│   └── server.py           # FastAPI server factory
├── tests/                  # Pytest test suite
├── web/index.html          # Operations console UI
├── cli.py                  # Main CLI entry point
├── simulator.py            # High-throughput simulation
├── enrichment.py           # Domain enrichment features
├── Dockerfile              # Container build definition
└── docker-compose.yml      # Multi-service orchestration
```

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
