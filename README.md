# 🧭 Waymark — AI-Native Reconnaissance Platform

> **Free, self-hosted reconnaissance platform for bug bounty hunters.** Waymark wraps open-source recon tools behind an intelligent agent that prioritizes targets using ROI scoring and teaches beginners the methodology at every step.

---

## ✨ Features

- **🤖 Adaptive Agent (ReAct Loop)** — Decides what to scan next based on results, not a fixed pipeline
- **🎯 ROI Scoring** — Prioritizes targets by vulnerability likelihood (admin panels, old tech, missing headers)
- **🎓 Educational System** — 33 built-in guides + real-time explanations in the Agent Decision Trail
- **🔄 Recurring Scans** — Daily/weekly/monthly automated re-scans with change detection
- **🔔 Notifications** — New subdomain alerts, content change detection, certificate expiry warnings
- **📡 Webhooks** — Slack and Discord integration with auto-format detection
- **🤖 Optional AI Assist** — Connect Groq (free) or Ollama (local) for richer explanations
- **🔌 Plugin System** — Extensible tool wrappers with standardized I/O
- **🛡️ Scope Management** — In-scope/out-of-scope rules with authorization attestation
- **📊 3-Tier Scan Governor** — Passive → Validation → Active with rate limiting

## 🔧 Integrated Tools

| Tool | Category | What It Does |
|---|---|---|
| subfinder | Subdomain Enumeration | Passive discovery from public sources |
| httpx | HTTP Probing | Checks which subdomains are alive + tech detection |
| ffuf | Directory Fuzzing | Finds hidden files, admin panels, API endpoints |
| nuclei | Vulnerability Scanning | Tests for known CVEs and misconfigurations |
| naabu | Port Scanning | Discovers open ports and services |
| katana | Web Crawling | Crawls websites to discover URLs and endpoints |
| dnsx | DNS Enumeration | DNS record enumeration and resolution |

## 🚀 Quick Start

### Native Setup (Kali Linux)

Waymark is designed to run natively on Kali Linux. Follow these steps:

1. **Install Prerequisites (System Packages)**
```bash
sudo apt update
sudo apt install postgresql redis
```

2. **Install Open-Source Recon Tools**
```bash
sudo apt install subfinder httpx-toolkit nuclei ffuf naabu katana dnsx
```

3. **Backend Setup**
```bash
# Clone the repo
git clone <your-repo-url> waymark
cd waymark/server

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --reload
```

4. **Frontend Setup (in a new terminal)**
```bash
cd waymark/client
npm install
npm run dev
```

Open http://localhost:3000

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Next.js    │────▶│   FastAPI    │────▶│  PostgreSQL  │
│   Frontend   │     │   Backend    │     │  (asyncpg)   │
│  :3000       │◀────│  :8000       │     └──────────────┘
└──────────────┘     │              │     ┌──────────────┐
     WebSocket ◀─────│  Scheduler   │────▶│    Redis     │
                     │  Agent Loop  │     │   (pubsub)   │
                     └──────────────┘     └──────────────┘
                            │
                     ┌──────┴──────┐
                     │   Plugins   │
                     │ subfinder   │
                     │ httpx, ffuf │
                     │ nuclei ...  │
                     └─────────────┘
```

## 📁 Project Structure

```
waymark/
├── client/                  # Next.js frontend
│   └── src/
│       ├── app/             # App Router pages
│       ├── components/      # Reusable components
│       └── lib/             # API client + utilities
├── server/                  # FastAPI backend
│   └── app/
│       ├── agent/           # Adaptive ReAct agent + LLM assist
│       ├── api/v1/          # REST API endpoints
│       ├── education/       # 33 built-in educational guides
│       ├── middleware/      # Rate limiting + security headers
│       ├── models/          # SQLAlchemy ORM models
│       ├── plugins/         # Tool wrappers (subfinder, httpx, etc.)
│       ├── schemas/         # Pydantic request/response schemas
│       ├── services/        # Business logic (scan, scheduler, etc.)
│       └── utils/           # Input validation + helpers
└── .env                     # Environment configuration
```

## 🎓 Educational Features

Waymark is designed to teach while it scans:

1. **Knowledge Base** — 33 searchable guides covering tools, concepts, and methodologies
2. **Agent Decision Trail** — Watch the AI agent explain every decision in real-time
3. **LearnMore Panels** — Expandable educational panels throughout the UI
4. **Education Notes** — Every agent decision includes a beginner-friendly explanation

## ⚙️ Configuration

All configuration is done via environment variables in `.env`:

```env
# Database
DATABASE_URL=postgresql+asyncpg://waymark:secret@localhost:5432/waymark

# Redis
REDIS_URL=redis://localhost:6379/0

# Optional: AI Assist (Gemini, OpenAI, Anthropic, Ollama)
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=ai-model
```

## 🕷️ Burp Suite Integration

Waymark integrates seamlessly with Burp Suite to act as your AI co-pilot during manual penetration testing.

### 1. The Burp Suite Extension
Waymark includes a custom Python extension for Burp Suite that automatically captures HTTP traffic and streams it to the Waymark AI engine for VAPT (Vulnerability Assessment and Penetration Testing) analysis.

1. In Burp Suite, go to **Extensions > BApp Store** and install **Jython**.
2. Go to **Extensions > Installed**, click **Add**.
3. Extension type: **Python**.
4. Extension file: Select `WaymarkBurpExtension.py` from the root of this repository.
5. Once loaded, you will see a new **Waymark** tab in Burp Suite. Traffic will now stream to Waymark's `/traffic` dashboard for AI analysis!

### 2. Routing Scans through Burp Suite
Want to see exactly what Waymark's recon tools (like `httpx`, `ffuf`, or `nuclei`) are sending to the target? You can route all automated tools through your Burp proxy.

1. Ensure Burp Suite proxy is running (default `127.0.0.1:8080`).
2. In Waymark, when starting a new scan, check the **"Route tools through Burp Proxy"** option.
3. Waymark will automatically download the Burp CA certificate (`/tmp/burp.crt`), configure the tools to trust it, and append the necessary proxy flags (e.g., `-proxy http://127.0.0.1:8080`).
4. Watch the tool traffic populate in Burp's Proxy HTTP History!

## 📖 API Documentation

When the server is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🤝 Contributing

### Adding a New Plugin

1. Create `app/plugins/your_tool.py`
2. Inherit from `ReconPlugin`
3. Implement `build_command()`, `parse_output()`, `validate_installed()`
4. Register in `app/plugins/registry.py`

## 📄 License

MIT License — free for personal and commercial use.
