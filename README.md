# Honey Token Generator

A Python CLI tool for deploying and cleaning up deception honey-tokens within an Active Directory (AD) environment. It creates fake user and service accounts in AD, assigns Service Principal Names (SPNs) for Kerberoasting detection, and injects realistic cached credentials (as separate logon sessions) onto workstations for Pass-the-Hash detection.

## Features

- **Decoy Provisioning** — Automatically creates randomized user/service accounts under a dedicated OU in Active Directory via LDAP/LDAPS.
- **Kerberoasting Trap** — Assigns specific SPNs to decoy accounts. When an attacker requests a Service Ticket for these SPNs, it triggers a Wazuh alert.
- **Pass-the-Hash Trap** — Injects realistic cached credentials onto endpoint workstations via WinRM using `Start-Process -Credential`. Each decoy appears as a separate logon session with NTLM/SHA1 hashes in LSASS — indistinguishable from genuine credentials. When an attacker dumps and uses these credentials, it triggers a Wazuh alert.
- **Cleanup** — Removes all deployed decoys (AD accounts + endpoint credentials + deployment record) and deletes the Wazuh CDB list file in one command.
- **Dry-Run Mode** — Simulates the full deploy/cleanup workflow without making any changes.
- **Idempotent** — Running deploy twice will not create duplicate accounts.

## Project Structure

```
Honey_Token_Generator/
├── honey_token_gen.py    # Main entry point (CLI + orchestration)
├── ldap_ops.py           # AD account creation, SPN assignment, cleanup
├── winrm_ops.py          # Cached credential injection/removal via WinRM
├── config.py             # Config loading and validation from JSON
├── config.example.json   # Example configuration template
├── requirements.txt      # Python dependencies
├── docs.md               # Technical code documentation
└── README.md             # This file
```

## Prerequisites

- **Python 3.10+**
- **Network access** to the Domain Controller on port `636` (LDAPS) or `389` (LDAP)
- **Network access** to Windows endpoints on port `5985` (WinRM HTTP) or `5986` (WinRM HTTPS)
- **Admin credentials** for both the Domain Controller and the endpoint workstations
- **WinRM enabled** on all target Windows endpoints

## Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Copy and customize the configuration file:
   ```bash
   cp config.example.json config.json
   ```

3. Edit `config.json` with your environment's actual values (DC IP, credentials, decoy definitions, endpoint details).

## Configuration

The configuration file (`config.json`) has three sections:

| Section | Purpose |
|---------|---------|
| `domain_controller` | DC connection details: IP, domain name, LDAPS port, admin credentials, decoy OU path |
| `decoys` | List of honey-token accounts to create: username, password, SPNs (optional — use an empty list for non-service accounts), description |
| `endpoints` | List of workstations to inject credentials: IP, hostname, WinRM credentials |

See `config.example.json` for a complete template.

## Usage

### Deploy Decoys

Deploy honey-token accounts to AD and inject cached credentials on endpoints:

```bash
python honey_token_gen.py deploy --config config.json
```

Test the configuration without making any changes:

```bash
python honey_token_gen.py deploy --config config.json --dry-run
```

**What deploy does:**
1. Connects to the Domain Controller via LDAPS
2. Creates a Decoy OU (e.g., `OU=Decoys,DC=NTT,DC=local`)
3. Deploys ALL decoys to ALL endpoints
4. For each decoy on each endpoint:
   - Creates an AD user account with SPNs in the Decoy OU
   - Injects a cached credential on the target workstation via WinRM
5. Writes `list.json` recording all deployed decoys and their workstation assignments
6. Writes `honey_tokens` CDB list file for Wazuh

### Cleanup Decoys

Remove all deployed decoys, clean AD, remove endpoint credentials, and delete the deployment record:

```bash
python honey_token_gen.py cleanup --config config.json
```

Test cleanup without making changes:

```bash
python honey_token_gen.py cleanup --config config.json --dry-run
```

**What cleanup does:**
1. Reads `list.json` to determine what was deployed
2. For each deployed decoy:
   - Kills the holder process on the workstation (removing the logon session from LSASS)
   - Deletes the AD user account from the Decoy OU
3. Deletes the Decoy OU if empty
4. Deletes `list.json`
5. Deletes `honey_tokens` (Wazuh CDB list)

### View Help

```bash
python honey_token_gen.py --help
python honey_token_gen.py deploy --help
python honey_token_gen.py cleanup --help
```

## Output Files

| File | Description |
|------|-------------|
| `list.json` | Deployment record — tracks deployed decoys and their workstation assignments. Created by `deploy`, deleted by `cleanup`. |
| `honey_tokens` | Wazuh CDB list — contains honey-token usernames in key:value format for Wazuh monitoring rules. Created by `deploy`, deleted by `cleanup`. |
| `honey_token_gen.log` | Detailed log file with DEBUG-level output for troubleshooting. |

## Wazuh Alerts

The generated `honey_tokens` file can be used directly as a Wazuh CDB list.
Ready-to-use manager rules, Windows agent collection configuration, and
deployment instructions are available in [`../Wazuh/README.md`](../Wazuh/README.md).

The supplied rules generate:

- Event 4624 (network logon through NTLM) with a decoy `targetUserName`:
  **Nghi vấn PtH attack**
- Event 4769 with a decoy `serviceName`: **Nghi vấn Kerberoasting attack**

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `LDAP connection refused` | Verify DC IP and port. Ensure LDAPS (636) is enabled on the DC. |
| `WinRM connection failed` | Ensure WinRM is enabled: run `winrm quickconfig` on the endpoint. |
| `Permission denied on AD` | Verify the admin account has permissions to create users in the target OU. |
| `Deployment record already exists` | Run `cleanup` before deploying again to avoid conflicts. |
