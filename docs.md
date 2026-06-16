# Honey Token Generator — Technical Documentation

This document provides a detailed technical explanation of how the Honey Token Generator application works, covering each module, its functions, and the overall workflow.

## Architecture Overview

The application is a Python CLI tool that runs on the **SIEM Server** (Ubuntu, 192.168.100.60) and interacts with two types of remote systems:

1. **Domain Controller (DC01)** via **LDAP/LDAPS** (port 636) — for creating and deleting AD user accounts with SPNs
2. **Windows Endpoints (WS01, WS02)** via **WinRM** (port 5985) — for injecting and removing cached credentials

```
┌──────────────────┐     LDAPS (636)     ┌──────────────────┐
│                  │────────────────────▶│                  │
│   SIEM Server    │                     │   DC01 (AD)      │
│   (This App)     │     WinRM (5985)    │                  │
│                  │────────────────────▶├──────────────────┤
│  192.168.100.60  │                     │   WS01           │
│                  │────────────────────▶│   WS02           │
└──────────────────┘                     └──────────────────┘
```

---

## Module Reference

### config.py — Configuration Loading

**Purpose:** Loads the JSON config file, parses it, and validates all required fields before the application proceeds.

#### Functions

**`load_config(config_path: str) -> dict`**
- Reads and parses the JSON config file
- Calls `_validate_config()` to check all fields
- Returns the parsed config dictionary
- Raises `FileNotFoundError` if file doesn't exist, `ValueError` if validation fails

**`_validate_config(config: dict) -> None`**
- Validates all required top-level keys: `domain_controller`, `deployment_settings`, `decoys`, `endpoints`
- Validates all required sub-keys within each section
- Checks `min_decoys_per_host <= max_decoys_per_host`
- Ensures all decoy usernames are **unique** (no duplicates)
- Validates SPN format using regex: `service/host` or `service/host:port`
- Warns if the decoy pool might be too small for the configured distribution settings

---

### ldap_ops.py — LDAP Operations

**Purpose:** Handles all interactions with Active Directory on the Domain Controller.

#### Functions

**`get_connection(ip, domain, admin_username, admin_password, port) -> Connection`**
- Establishes an authenticated LDAP/LDAPS connection
- Uses SSL when port is 636
- Sets `raise_exceptions=True` so LDAP errors are raised as Python exceptions

**`create_ou_if_not_exists(conn, decoy_ou, dry_run) -> None`**
- Checks if the Decoy OU exists by searching from the **parent DN** with `LEVEL` scope
- Creates the OU only if it doesn't exist
- Handles `LDAPEntryAlreadyExistsResult` for race conditions

**`deploy_ldap_decoy(conn, decoy, decoy_ou, domain_name, dry_run) -> None`**
- Creates a single honey-token user account in Active Directory
- If the account already exists, updates its description and SPNs (idempotent)
- Creation process:
  1. Creates the user object with standard AD attributes
  2. Sets the password (encoded as UTF-16LE, double-quoted)
  3. Enables the account (UAC flag 512 = NORMAL_ACCOUNT)
  4. Assigns SPNs for Kerberoasting detection
- If any configuration step fails after account creation, **rolls back** by deleting the partially-created account

**`cleanup_ldap_decoy(conn, username, decoy_ou, dry_run) -> None`**
- Deletes a specific decoy account by its CN
- Skips silently if the account doesn't exist (idempotent)

**`delete_ou_if_empty(conn, decoy_ou, dry_run) -> None`**
- Checks for child objects inside the OU using `LEVEL` scope search
- Only deletes the OU if it contains zero children
- Warns if the OU still has children

**`_account_exists(conn, dn) -> bool`**
- Helper function that checks if an object exists at a specific DN
- Uses `BASE` scope search (correct approach for exact DN lookup)
- Handles `LDAPNoSuchObjectResult` gracefully

---

### winrm_ops.py — WinRM Operations

**Purpose:** Handles credential injection and removal on Windows endpoints.

#### Functions

**`get_winrm_session(ip, username, password, transport) -> Session`**
- Creates a WinRM session using HTTP on port 5985
- Returns a `winrm.Session` object

**`inject_credential_decoy(session, domain, username, password, dry_run) -> None`**
- Injects a fake cached credential using `cmdkey /add`
- Uses a **unique target per decoy**: `username.domain` (e.g., `sql-decoy.NTT.local`)
- This prevents multiple decoys on the same host from overwriting each other
- After injection, calls `_verify_credential()` to confirm it was stored

**`remove_credential_decoy(session, domain, username, dry_run) -> None`**
- Removes a specific credential using `cmdkey /delete` with the same unique target
- Tolerates non-zero exit codes (the credential might already be removed)

**`_build_target(username, domain) -> str`**
- Builds the unique cmdkey target string: `{username}.{domain}`

**`_verify_credential(session, target, user_principal) -> None`**
- Runs `cmdkey /list` and checks if the expected target appears in the output
- Logs a warning if verification fails (may occur due to user session differences)

**`_run_cmd(session, command, args) -> tuple`**
- Executes a cmd.exe command on the remote host
- Returns `(status_code, stdout, stderr)`

**`_run_ps(session, script) -> tuple`**
- Executes a PowerShell script on the remote host
- Returns `(status_code, stdout, stderr)`

---

### honey_token_gen.py — Main Entry Point

**Purpose:** CLI parsing, logging setup, and orchestration of deploy/cleanup workflows.

#### Functions

**`setup_logging() -> None`**
- Configures dual logging: console (INFO level) + file (DEBUG level)
- Log file: `honey_token_gen.log`

**`_distribute_decoys(decoys_pool, endpoints, min_per_host, max_per_host) -> dict`**
- Shuffles the decoy pool randomly
- Assigns a random count of decoys (between min and max) to each endpoint
- If the pool runs out, remaining endpoints get fewer decoys (no wrapping/reuse)
- Returns a mapping: `{hostname: [decoy1, decoy2, ...]}`

**`cmd_deploy(args) -> None`**
- Full deploy orchestration:
  1. Loads and validates config
  2. Checks that no existing deployment exists (prevents double-deploy)
  3. Connects to DC via LDAP
  4. Creates the Decoy OU
  5. Distributes decoys across endpoints
  6. For each endpoint: connects via WinRM, creates AD accounts, injects credentials
  7. Writes `list.json`
  8. Prints a summary with success/failure counts

**`cmd_cleanup(args) -> None`**
- Full cleanup orchestration:
  1. Reads `list.json` for deployed decoys
  2. Loads config for connection credentials
  3. For each decoy: removes credential (WinRM) + deletes AD account (LDAP)
  4. Deletes Decoy OU if empty
  5. Deletes `list.json`
  6. Prints a summary

**`main() -> None`**
- Parses CLI arguments using argparse with subcommands (`deploy`, `cleanup`)
- Dispatches to the appropriate command handler

---

## Workflow Diagrams

### Deploy Workflow

```
User runs: python honey_token_gen.py deploy --config config.json
│
├── Load config.json → validate all fields
├── Check list.json doesn't exist (prevent double-deploy)
├── Connect to DC01 via LDAPS
├── Create OU=Decoys if not exists
├── Shuffle decoy pool → assign random count per endpoint
│
├── For WS01 (assigned: sql-decoy, backup-admin):
│   ├── Connect to WS01 via WinRM
│   ├── Create 'sql-decoy' in AD → inject credential on WS01
│   └── Create 'backup-admin' in AD → inject credential on WS01
│
├── For WS02 (assigned: sql-decoy2):
│   ├── Connect to WS02 via WinRM
│   └── Create 'sql-decoy2' in AD → inject credential on WS02
│
├── Write list.json (deployment record)
└── Print summary
```

### Cleanup Workflow

```
User runs: python honey_token_gen.py cleanup --config config.json
│
├── Read list.json → find 3 deployed decoys
├── Load config.json → get connection credentials
├── Connect to DC01 via LDAPS
│
├── sql-decoy on WS01:
│   ├── Connect to WS01 via WinRM → cmdkey /delete:sql-decoy.NTT.local
│   └── Delete CN=sql-decoy from AD
│
├── backup-admin on WS01:
│   ├── (reuse WS01 session) → cmdkey /delete:backup-admin.NTT.local
│   └── Delete CN=backup-admin from AD
│
├── sql-decoy2 on WS02:
│   ├── Connect to WS02 via WinRM → cmdkey /delete:sql-decoy2.NTT.local
│   └── Delete CN=sql-decoy2 from AD
│
├── Delete OU=Decoys (if empty)
├── Delete list.json
└── Print summary
```

---

## Integration with Wazuh

After deployment, the `list.json` file contains all deployed honey-token usernames and their SPNs. Wazuh uses this information (via CDB lists) to monitor for unauthorized interactions:

- **Event 4769** (TGS-REQ) with a honey-token SPN → Kerberoasting detected
- **Event 4776** (NTLM validation) with a honey-token username → Pass-the-Hash detected
- **Event 4624** (Successful logon, type 3) with a honey-token username → Pass-the-Hash detected

When a match is found, Wazuh triggers an Active Response script that calls the pfSense API to block the attacker's IP address.
