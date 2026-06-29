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
- Validates all required top-level keys: `domain_controller`, `decoys`, `endpoints`
- Validates all required sub-keys within each section
- Ensures all decoy usernames are **unique** (no duplicates)
- SPNs are **optional** — missing or empty list is allowed (non-service user accounts)
- If SPNs are provided, validates format using regex: `service/host` or `service/host:port`

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

**Purpose:** Handles credential injection and removal on Windows endpoints. Each honey-token credential is injected by launching a hidden background PowerShell process under the decoy user's credentials via `Start-Process -Credential`. This creates a real Interactive logon session (Type 2) in LSASS, causing each decoy to appear as a separate session with NTLM/SHA1 hashes — indistinguishable from genuine cached credentials.

#### Functions

**`get_winrm_session(ip, username, password, transport) -> Session`**
- Creates a WinRM session using HTTP on port 5985
- Returns a `winrm.Session` object

**`inject_credential_decoy(session, domain, username, password, dry_run) -> None`**
- Launches a hidden background PowerShell process under the decoy user's credentials via `Start-Process -Credential`
- This creates a genuine Interactive logon session (Type 2) in LSASS with NTLM and SHA1 hashes
- Each decoy gets its own separate logon session with a unique Authentication ID
- The holder process PID is saved to the registry at `HKLM:\SOFTWARE\HoneyTokens\<username>` for cleanup

**`remove_credential_decoy(session, domain, username, dry_run) -> None`**
- Reads the holder process PID from the registry at `HKLM:\SOFTWARE\HoneyTokens\<username>`
- Kills the process (which destroys the logon session and purges credentials from LSASS)
- Removes the registry entry
- Cleans up the `HKLM:\SOFTWARE\HoneyTokens` key if no more entries remain
- Tolerates missing processes or registry entries (idempotent)

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

**`cmd_deploy(args) -> None`**
- Full deploy orchestration:
  1. Loads and validates config
  2. Checks that no existing deployment exists (prevents double-deploy)
  3. Connects to DC via LDAP
  4. Creates the Decoy OU
  5. Creates all AD accounts first (idempotent)
  6. For each endpoint: connects via WinRM, injects all decoy credentials
  7. Writes `list.json` (deployment record)
  8. Writes `honey_tokens` (Wazuh CDB list — unique usernames in `key:value` format)
  9. Prints a summary with success/failure counts

**`cmd_cleanup(args) -> None`**
- Full cleanup orchestration:
  1. Reads `list.json` for deployed decoys
  2. Loads config for connection credentials
  3. For each decoy: kills holder process (WinRM) + deletes AD account (LDAP)
  4. Deletes Decoy OU if empty
  5. Deletes `list.json`
  6. Deletes `honey_tokens` (CDB list)
  7. Prints a summary

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
│
├── Create all AD accounts (idempotent):
│   ├── Create 'sql-decoy' with SPN in AD
│   ├── Create 'backup-svc' with SPN in AD
│   ├── Create 'john.nguyen' (no SPN) in AD
│   └── Create 'admin.le' (no SPN) in AD
│
├── For WS01:
│   ├── Connect to WS01 via WinRM
│   ├── Inject credential for 'sql-decoy' (Start-Process -Credential)
│   ├── Inject credential for 'backup-svc'
│   ├── Inject credential for 'john.nguyen'
│   └── Inject credential for 'admin.le'
│
├── For WS02:
│   ├── Connect to WS02 via WinRM
│   ├── Inject credential for 'sql-decoy'
│   ├── Inject credential for 'backup-svc'
│   ├── Inject credential for 'john.nguyen'
│   └── Inject credential for 'admin.le'
│
├── Write list.json (deployment record)
├── Write honey_tokens (Wazuh CDB list)
└── Print summary
```

### Cleanup Workflow

```
User runs: python honey_token_gen.py cleanup --config config.json
│
├── Read list.json → find deployed decoys
├── Load config.json → get connection credentials
├── Connect to DC01 via LDAPS
│
├── For each decoy on each workstation:
│   ├── Connect to workstation via WinRM
│   ├── Kill holder process (PID from registry) → credential removed from LSASS
│   └── Delete AD account from Decoy OU
│
├── Delete OU=Decoys (if empty)
├── Delete list.json
├── Delete honey_tokens (CDB list)
└── Print summary
```

---

## Integration with Wazuh

After deployment, the application generates a `honey_tokens` file in Wazuh CDB list format (`key:value` pairs). This file can be copied directly to the Wazuh Manager at `/var/ossec/etc/lists/honey_tokens` for monitoring. The `list.json` file contains detailed deployment information (usernames, SPNs, workstation assignments).

Wazuh uses the CDB list to monitor for unauthorized interactions with honey-token accounts:

- **Event 4769** (TGS-REQ) with a honey-token SPN → Kerberoasting detected
- **Event 4776** (NTLM validation) with a honey-token username → Pass-the-Hash detected
- **Event 4624** (Successful logon, type 3) with a honey-token username → Unauthorized access detected

When a match is found, Wazuh triggers an Active Response script that calls the pfSense API to block the attacker's IP address.
