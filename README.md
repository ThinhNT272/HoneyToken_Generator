# Honey Token Generator

A Python CLI tool for deploying and cleaning up deception honey-tokens within an Active Directory (AD) environment. It creates fake user and service accounts in AD, assigns Service Principal Names (SPNs) for Kerberoasting detection, and injects cached credentials onto workstations for Pass-the-Hash detection.

## Features

- **Decoy Provisioning** — Automatically creates randomized user/service accounts under a dedicated OU in Active Directory via LDAP/LDAPS.
- **Kerberoasting Trap** — Assigns specific SPNs to decoy accounts. When an attacker requests a Service Ticket for these SPNs, it triggers a Wazuh alert.
- **Pass-the-Hash Trap** — Injects fake cached credentials onto endpoint workstations via WinRM using Windows Credential Manager (`cmdkey`). When an attacker dumps and uses these credentials, it triggers a Wazuh alert.
- **Random Distribution** — Shuffles the decoy pool and assigns a random number of decoys (configurable min/max) to each endpoint.
- **Cleanup** — Removes all deployed decoys (AD accounts + endpoint credentials + deployment record) in one command.
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

The configuration file (`config.json`) has four sections:

| Section | Purpose |
|---------|---------|
| `domain_controller` | DC connection details: IP, domain name, LDAPS port, admin credentials, decoy OU path |
| `deployment_settings` | `min_decoys_per_host` and `max_decoys_per_host` — controls randomization |
| `decoys` | List of honey-token accounts to create: username, password, SPNs, description |
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
3. Randomly distributes decoys across endpoints
4. For each assigned decoy:
   - Creates an AD user account with SPNs in the Decoy OU
   - Injects a cached credential on the target workstation via WinRM
5. Writes `list.json` recording all deployed decoys and their workstation assignments

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
   - Removes the cached credential from the workstation via WinRM
   - Deletes the AD user account from the Decoy OU
3. Deletes the Decoy OU if empty
4. Deletes `list.json`

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
| `honey_token_gen.log` | Detailed log file with DEBUG-level output for troubleshooting. |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `LDAP connection refused` | Verify DC IP and port. Ensure LDAPS (636) is enabled on the DC. |
| `WinRM connection failed` | Ensure WinRM is enabled: run `winrm quickconfig` on the endpoint. |
| `Permission denied on AD` | Verify the admin account has permissions to create users in the target OU. |
| `Deployment record already exists` | Run `cleanup` before deploying again to avoid conflicts. |
| `Decoy pool exhausted` | Add more decoy definitions to config, or reduce `max_decoys_per_host`. |
