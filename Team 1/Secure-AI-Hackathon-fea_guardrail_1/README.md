# PQC Security Assessment Workspace

An AI-powered security engineering platform for post-quantum cryptography (PQC) readiness assessment. It combines CBOM analysis, SonarQube integration, NIST knowledge retrieval (RAG), and LLM-driven report generation with built-in AI guardrails. 

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CI/CD Pipeline                            │
│                  (.github/workflows/pqc-security-scan.yml)       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CBOM Parser ──► Rule Engine ──► Remediation Engine              │
│       │                                                          │
│  SonarQube Parser ──► Sonar Integration                          │
│       │                                                          │
│  NIST PDFs ──► Ingest Documents ──► Vector DB (RAG)              │
│       │                                                          │
│       └──────────► AI Agent (Mistral LLM) ◄── RAG Retriever     │
│                          │                                       │
│                    ┌─────┴─────┐                                 │
│                    │ Guardrails │                                 │
│                    ├───────────┤                                 │
│                    │ 1. Prompt Injection Protection               │
│                    │ 2. Hallucination Detection                   │
│                    │ 3. Output Validation                         │
│                    └───────────┘                                 │
│                          │                                       │
│                    Security Report + Guardrail Results            │
│                          │                                       │
│                    PR Comment (GitHub)                            │
└─────────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
Secure-AI-Hackathon/
├── .github/workflows/
│   └── pqc-security-scan.yml        # CI pipeline (runs on PR/push)
├── ai-security-copilot/
│   ├── agent.py                      # AI agent - orchestrates LLM report generation
│   ├── guardrails.py                 # AI guardrails (hallucination, injection, output)
│   ├── cbom_parser.py                # Parses CBOM JSON for cryptographic assets
│   ├── rule_engine.py                # Evaluates assets against PQC risk rules
│   ├── remediation_engine.py         # Generates migration/remediation plans
│   ├── sonarqube_parser.py           # Parses SonarQube vulnerability reports
│   ├── sonar_integration.py          # Combines CBOM + SonarQube context
│   ├── ingest_documents.py           # Indexes NIST PDFs into vector DB (RAG)
│   ├── rag_retriever.py              # Retrieves NIST evidence via similarity search
│   ├── query_knowledge_base.py       # Interactive RAG query tool
│   ├── embedding_config.py           # HuggingFace embedding model configuration
│   ├── security_gate.py              # CI merge gate (pass/fail on security score)
│   ├── pqc_rules.json                # PQC risk rules with NIST references
│   ├── app-cbom-final.json           # CBOM input (cryptographic inventory)
│   ├── requirements.txt              # Python dependencies
│   ├── agent/tools/
│   │   └── cbom_scanner.py           # CBOM scanning tool
│   ├── config/
│   │   └── rules.json                # Additional rule configuration
│   ├── input/
│   │   ├── sonarqube-report.json     # SonarQube code analysis report
│   │   ├── sonarqube-vulnerabilities.json
│   │   └── sonarqube-hotspots.json   # Security hotspot findings
│   ├── knowledge_base/
│   │   ├── nist/
│   │   │   ├── NIST.FIPS.203.pdf     # ML-KEM standard
│   │   │   └── NIST.FIPS.204.pdf     # ML-DSA standard
│   │   └── migration/
│   │       └── pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf
│   ├── rules/
│   │   └── pqc_rules.yaml           # YAML rule definitions
│   └── test/
│       └── VulnerableCrypto.java     # Sample vulnerable code for testing
├── cbomkit-theia/                    # CBOM tooling (Go-based scanner)
├── wrongsecrets/                     # Intentionally vulnerable reference app
└── README.md
```

## Pipeline Steps

| Step | Script | Purpose |
|------|--------|---------|
| 1 | `cbom_parser.py` | Extract cryptographic assets from CBOM |
| 2 | `sonarqube_parser.py` | Parse SonarQube vulnerability/hotspot reports |
| 3 | `sonar_integration.py` | Merge CBOM and SonarQube findings into unified context |
| 4 | `rule_engine.py` | Evaluate assets against PQC risk rules |
| 5 | `remediation_engine.py` | Generate prioritized remediation plan |
| 6 | `ingest_documents.py` | Index NIST PDFs into ChromaDB vector store |
| 7 | `agent.py` | Generate AI security report with guardrail validation |
| 8 | `security_gate.py` | CI merge gate (blocks PR if score < threshold) |

## AI Guardrails

The system includes three guardrails that validate AI-generated output:

| Guardrail | Phase | What it checks |
|-----------|-------|---------------|
| Prompt Injection Protection | Pre-generation | Scans RAG documents and SonarQube data for injection attempts before they reach the LLM |
| Hallucination Detection | Post-generation | Verifies algorithms, NIST references, file paths, and risk levels against source evidence |
| Output Validation | Post-generation | Ensures report has required sections, valid score, no fabricated references |

Results are saved to `output/guardrail_results.json` and displayed in the PR comment.

## Quick Start

### Prerequisites

- Python 3.11+
- Mistral API key (set as `MISTRAL_API_KEY` environment variable)

### Install Dependencies

```bash
cd ai-security-copilot
pip install -r requirements.txt
```

### Run Locally

```bash
cd ai-security-copilot

# Step 1: Parse and analyze
python cbom_parser.py
python sonarqube_parser.py
python sonar_integration.py
python rule_engine.py
python remediation_engine.py

# Step 2: Build knowledge base (required once)
python ingest_documents.py

# Step 3: Generate report with guardrails
python agent.py
```

Outputs are written to `ai-security-copilot/output/`:
- `quantum_security_report.md` — full security assessment
- `guardrail_results.json` — guardrail validation results
- `security_findings.json` — raw PQC findings
- `remediation_plan.json` — migration plan

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/pqc-security-scan.yml`) runs automatically on:
- Pull requests to `main`
- Pushes to any branch

It executes the full pipeline and posts the security report + guardrail validation table as a PR comment.

### Required Secrets

| Secret | Purpose |
|--------|---------|
| `MISTRAL_API_KEY` | Mistral AI API access for report generation |

## Key Technologies

- **LLM**: Mistral (via `mistralai` SDK)
- **RAG**: LangChain + ChromaDB + HuggingFace embeddings (`all-MiniLM-L6-v2`)
- **Knowledge Base**: NIST FIPS 203, FIPS 204, SP 1800-38B
- **Code Analysis**: SonarQube findings integration
- **Cryptographic Inventory**: CBOM (Cryptographic Bill of Materials)
- **CI/CD**: GitHub Actions with PR comment integration

## Security Focus

This project helps teams:
- Inventory cryptographic dependencies from CBOM data
- Identify algorithms vulnerable to quantum computing attacks
- Prioritize migration by risk level and NIST guidance
- Generate actionable, evidence-backed remediation plans
- Validate AI outputs to prevent hallucinated security advice
- Automate security assessment in CI/CD pipelines
