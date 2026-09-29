# Entra ID / Azure Security Auditor 🛡️

A high-performance Python security auditing and analysis tool for Microsoft Entra ID (formerly Azure AD). This tool securely authenticates via Microsoft Graph, extracts core identity and access configurations, performs deep heuristic analysis—including robust **Conditional Access & MFA policy profiling**—and generates structured audit reports.

---

## 🌟 Key Features

- **Deep Conditional Access Analysis**: Goes beyond basic baseline checks. Evaluates policy conditions, actions (Grant/Block), risk triggers, exclusions, and auth flows (e.g., Device Code, Legacy Auth).
- **Inactivity & Stale App Detection**: Tracks inactive member accounts, guests, and unutilized Service Principals via Graph sign-in logs and beta telemetry.
- **Privileged Identity Inspection**: Evaluates PIM (Privileged Identity Management) assignments, direct/group-based role assignments, and permanent vs. time-bound access.
- **Resilient Microsoft Graph Ingestion**: Handles Microsoft Graph throttling, API pagination, and feature downgrades gracefully (e.g., fallback when Entra ID P2/P1 features are missing).
- **Multi-Format Reporting**: Generates granular audit reports in **JSON** or **CSV**, exposes a native **REST API**, and persists snapshot data in **PostgreSQL**.
- **Automated Testing Suite**: Includes comprehensive unit tests for pure parsers, baseline evaluators, and API endpoints.

---

## 🏗️ Architecture & Project Structure

```text
entra_auditor/
├── graph/
│   ├── client.py           # MSAL authentication & HTTP wrapper
│   └── collectors.py       # Async/Sync Graph API query engine & paginators
├── models.py               # Pure Pydantic data models & snapshot containers
├── checks/
│   ├── _common.py          # Shared audit configurations & severity constants
│   ├── ca_analysis.py      # Core Conditional Access evaluator & condition parser
│   ├── inactive_users.py   # User inactivity & stale guest checking logic
│   ├── privileged.py       # PIM & privileged role assignment evaluator
│   ├── mfa_ca.py           # MFA registration & CA baseline security rules
│   └── stale_apps.py       # Service principal sign-in & secret expiration rules
├── storage/                # PostgreSQL persistence layer
├── api/                    # REST API endpoints (FastAPI)
└── tests/                  # Pytest test suite for parsers, rules, and mocks
```

### Core Design Principles

1. **Separation of Collection & Finding Logic**: Graph collection outputs pure models (`TenantSnapshot`). Finding checks run statically on snapshots without making active network calls.
2. **Graceful Degradation (`None` vs Empty List)**: If an API endpoint fails due to missing licenses or 403 Forbidden permissions, the model attribute is set to `None` rather than `[]`. Checks distinguish between "No policies present" vs "Could not read policies".

---

## 🧠 Expanded Conditional Access (CA) Engine

Most security tools only check if an MFA policy exists. **Entra Security Auditor** parses and profiles every policy condition to expose blind spots, bypasses, and risk configurations.

### Key Policy Inspection Capabilities

| Capability | What It Analyzes | Why It Matters |
| :--- | :--- | :--- |
| **Action & Grant Controls** | Identifies whether access is **Blocked**, requires **MFA**, or uses an **Authentication Strength** (e.g., FIDO2 / Phishing-Resistant). | Distinguishes between weak legacy MFA and phishing-resistant controls. |
| **Exclusions & Bypasses** | Extracts explicit User, Group, Role, and Directory Exclusions. | Prevents silent bypasses where a Global Admin or group avoids baseline controls. |
| **Condition Analysis** | Analyzes targeted Apps, Platforms, Locations, Client Types, and Risk Levels (User Risk / Sign-in Risk). | Surfaces gaps like unhandled legacy auth, unprotected Azure Management interfaces, or missing device controls. |
| **Auth-Flow Detection** | Flags high-risk authentication flows such as **Device Code Flow** or **Transfer Token Flow**. | Detects vulnerability to modern phishing and device code phishing attacks. |

### Baseline Security Rules (`mfa_ca.py`)

The auditor evaluates policies against declarative security baselines:
- `CA_NO_MFA_ALL_USERS`: All users / All apps MFA enforcement.
- `CA_NO_MFA_ADMINS`: Strict MFA requirement across all administrative roles.
- `CA_NO_LEGACY_AUTH_BLOCK`: Complete blockage of legacy authentication protocols.
- `CA_NO_AZURE_MANAGEMENT_MFA`: Mandatory MFA on Azure Portal, CLI, and ARM interfaces.
- `CA_NO_SECURITY_INFO_PROTECTION`: Protection of MFA method registration flows.
- `CA_EXCLUDED_FROM_ALL_POLICIES`: Cross-policy correlation identifying principals excluded from **all** enforced policies.

---

## 📋 Required Entra ID Permissions

To run a complete tenant audit, register an application in Entra ID with the following **Application Permissions**:

| Permission Name | Type | Usage |
| :--- | :--- | :--- |
| `User.Read.All` | Application | Read user profiles & object details |
| `AuditLog.Read.All` | Application | Audit sign-in logs and user activity (`signInActivity`) |
| `Directory.Read.All` | Application | Read directory roles, groups, and service principals |
| `Policy.Read.All` | Application | Parse Conditional Access policies & Security Defaults |
| `RoleAssignmentSchedule.Read.Directory` | Application | Read PIM (Privileged Identity Management) schedules |
| `Reports.Read.All` | Application | Access service principal sign-ins and MFA registration reports |

> **Note**: Service principal sign-in telemetry uses the Microsoft Graph `/beta` endpoint (`servicePrincipalSignInActivities`). If unavailable, `sp_sign_in_data_available` is marked `False` and skips false-positive flags.

---

## 🚀 Quickstart Guide

### 1. Installation

Clone the repository and install dependencies using `pip`:

```bash
git clone https://github.com/your-org/entra-auditor.git
cd entra-auditor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package and dependencies
pip install -e .
```

### 2. Environment Setup

Configure your tenant credentials in an `.env` file or export them directly:

```env
AZURE_TENANT_ID="your-tenant-id-guid"
AZURE_CLIENT_ID="your-app-registration-client-id"
AZURE_CLIENT_SECRET="your-app-registration-client-secret"
DATABASE_URL="postgresql://user:password@localhost:5432/entra_audit"
```

### 3. Basic Execution (Python API)

Collect tenant metrics and output findings:

```python
from datetime import datetime, timezone
from entra_auditor.graph import GraphClient, create_token_provider
from entra_auditor.graph.collectors import TenantCollector
from entra_auditor.checks.mfa_ca import check_mfa_ca
from entra_auditor.checks._common import AuditConfig

tenant_id = "your-tenant-id-guid"
provider = create_token_provider()

# 1. Collect Snapshot
with GraphClient(provider) as graph:
    snapshot = TenantCollector(graph, progress=print).collect(tenant_id)

# 2. Execute Audit Checks
now = datetime.now(timezone.utc)
cfg = AuditConfig()

findings = check_mfa_ca(snapshot, now=now, cfg=cfg)

# 3. Print Findings Summary
for finding in findings:
    print(f"[{finding.severity.upper()}] {finding.check_id}: {finding.title}")
```

### 4. Running Tests

Run unit tests and parser validations:

```bash
pytest tests/
```

---

## 📊 Output Formats

Findings are structured around standardized severity levels (`critical`, `high`, `medium`, `low`, `info`).

### Example JSON Finding Output

```json
{
  "check_id": "CA_EXCLUDED_FROM_ALL_POLICIES",
  "severity": "high",
  "resource_type": "tenant",
  "resource_id": "00000000-0000-0000-0000-000000000000",
  "title": "2 account(s)/group(s) are excluded from every enforced all-users Conditional Access policy",
  "evidence": {
    "policies_compared": [
      "Require MFA for All Users",
      "Block Legacy Authentication"
    ],
    "excluded": [
      "BreakGlass Admin 1 (User)",
      "Legacy Service Account Group (Group)"
    ],
    "user_ids": ["a1b2c3d4-0000-0000-0000-000000000000"],
    "group_ids": ["e5f6g7h8-0000-0000-0000-000000000000"]
  },
  "remediation": "Fine only for monitored break-glass accounts (alert on every sign-in). Otherwise remove the exclusions."
}
```

---

## 🛠️ REST API & Storage

The included REST service provides endpoints to trigger background tenant audits, query historical runs, and pull findings over HTTP:

```bash
# Start REST service
uvicorn entra_auditor.api.main:app --reload

# Trigger an audit via API
curl -X POST "http://localhost:8000/api/v1/audit/trigger" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "your-tenant-id-guid"}'
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).