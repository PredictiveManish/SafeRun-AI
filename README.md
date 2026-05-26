# SafeRun AI

Secure sandbox execution for AI-generated Python code.

---

## Overview

SafeRun AI is a local-first developer tool that executes untrusted Python code inside a hardened Docker sandbox. It combines static AST scanning, policy enforcement, resource limits, and audit logging to protect the host system from malicious or buggy AI-generated code.

The tool is designed for developers, AI engineers, and local LLM users who need to test AI-generated code without risking their machine.

---

## Problem

Large language models can generate code that:

- Deletes or modifies files (`os.remove`, `shutil.rmtree`)
- Spawns shells (`subprocess.run`)
- Exfiltrates data via network requests
- Consumes all CPU/memory (fork bombs, infinite loops)
- Uses `eval`/`exec` to bypass static checks

Running such code directly on your host is dangerous. SafeRun AI provides a layered defense.

---

## Threat Model

We assume the attacker (or the AI model) can generate arbitrary Python code. The sandbox aims to prevent:

- Persistence – modifying system files or installing backdoors
- Exfiltration – sending data to external networks
- Resource exhaustion – CPU/memory/disk DoS
- Privilege escalation – breaking out of the container to the host

**Note:** This is not a perfect sandbox (see Limitations). It is a layered defense suitable for local development.

---

**Security layers:**

- AST-based static scanner (detects dangerous imports/calls/paths)
- YAML policy engine (allow/block lists, resource limits)
- Docker container with:
  - Non-root user (`sandbox`, UID 1000)
  - Read-only root filesystem
  - No network access (by default)
  - Memory/CPU limits
  - Process limits (pids-limit=64)
  - No privileged mode, no host devices
- Optional Sarvam AI explanations (falls back to local rules)

---

## Features

- Execute untrusted Python in isolated Docker sandbox
- Static risk scanner with risk levels: LOW, MEDIUM, HIGH, BLOCKED
- Configurable policy (allowed imports, blocked calls, resources)
- Runtime monitoring (stdout, stderr, exit code, execution time)
- SQLite audit history with last 20 executions shown
- Optional Sarvam AI integration (graceful fallback)
- Works fully offline (no API key required)
- Developer-friendly Streamlit UI
- Export execution reports as JSON

---

## Quick Startup:

```bash
# Install CLI
pip install saferun-ai

# Use immediately (connects to hosted backend)
saferun script.py
saferun run script.py

# Or use local backend
export SAFERUN_API_URL=http://localhost:8000
saferun script.py
```
---

---
Try Online: saferun-ai.onrender.com
---

## Tech Stack

| Component       | Technology                     |
|----------------|--------------------------------|
| Backend        | Python 3.11+, FastAPI, Pydantic|
| Sandbox        | Docker SDK for Python          |
| Scanner        | Python `ast` module            |
| Policy         | PyYAML                         |
| Database       | SQLAlchemy + SQLite            |
| Frontend       | Streamlit                      |
| AI (optional)  | Sarvam AI REST API             |
| Testing        | pytest                         |

---

## Setup

### Prerequisites

- Python 3.11 or higher
- Docker Desktop (or Docker Engine) running
- (Optional) Sarvam AI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/predictivemanish/saferun-ai.git
cd saferun-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Build the sandbox Docker image
cd sandbox_image
docker build -t saferun-sandbox:latest .
cd ..

# Set environment variables (optional)
cp .env.example .env
# Edit .env if you have a Sarvam API key (otherwise leave empty)

# Initialize database (auto-creates saferun.db)
python -c "from backend.database import init_db; init_db()"
```

--
### How to run?

- Terminal 1 (Backend)
```
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

- Terminal 2 (Frontend)
```
streamlit run frontend/app.py
```

---
## Usage
1. Paste Python code into the editor.

2. Click Scan Only to see static analysis results and risk level.

3. Click Execute in Sandbox to run the code inside Docker.

4. If the code is blocked, check the Override safety blocks checkbox to force execution (use with caution).

5. View execution results, stdout/stderr, and execution time.

6. Scroll down to see the execution history (last 20 runs).

---
## Project Structure
```
saferun-ai/
├── README.md
├── requirements.txt
├── .env.example
├── docker-compose.yml
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── scanner.py
│   ├── sandbox.py
│   ├── policy_engine.py
│   ├── audit.py
│   ├── explanations.py
│   ├── utils.py
│   └── policies/
│       └── default_policy.yaml
├── frontend/
│   ├── __init__.py
│   └── app.py
├── sandbox_image/
│   └── Dockerfile
├── tests/
│   ├── test_scanner.py
│   ├── test_policy.py
│   └── test_api.py
├── examples/
│   ├── safe_example.py
│   ├── dangerous_example.py
│   ├── timeout_example.py
│   └── network_example.py
├── tests/
│    ├── test_scanner.py
```


### Disclaimer
```
Disclaimer
No sandbox is completely secure. Running untrusted code always carries residual risk. Always review AI-generated code before execution, even when using this tool. The authors are not liable for any damages arising from its use.
```