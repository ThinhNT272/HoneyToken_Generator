# Honey Token Generator

**Honey Token Generator** is a Python CLI tool designed to run directly on an Active Directory **Domain Controller (DC)**. It creates and manages decoy accounts (honey-tokens) to detect cyber attacks in your network.

The tool creates fake user and service accounts in Active Directory, assigns Service Principal Names (SPNs) to catch **Kerberoasting** attacks, and uses **Group Policy Objects (GPO)** and a **Network Share** to place fake credentials into the LSASS memory of domain workstations to catch **Pass-the-Hash (PtH)** attacks.

---

## How It Works

### 1. Architecture Overview

Instead of connecting to each machine individually over WinRM, the tool runs on the Domain Controller and uses Active Directory **Group Policy Objects (GPO)** to automatically deploy decoy credentials to all workstations.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Domain Controller (DC)                          │
│                                                                        │
│  1. Create Decoy Accounts & SPNs ──> AD OU (OU=Decoys,DC=domain,DC=com)│
│  2. Copy Script & Config         ──> Public Share (C:\Shares\Public)   │
│  3. Setup Startup Script         ──> GPO (HoneyToken_GPO) -> SYSVOL    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                       Group Policy Applied (GPO)
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Target Workstations / Clients                    │
│                                                                        │
│  4. Run `inject_decoy.ps1` as SYSTEM at startup                        │
│  5. Read `decoys.json` from Network Share                              │
│  6. Grant `SeBatchLogonRight` using Win32 API                          │
│  7. Create Scheduled Tasks running as Decoy Accounts                   │
│  8. Fake credentials loaded into LSASS memory (Ready for PtH trap)     │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 2. Deployment Process (`deploy`)

When you run `python honey_token_gen.py deploy`:

1. **Create Decoy OU**: Creates a dedicated Organizational Unit (OU) in Active Directory (e.g., `OU=Decoys,DC=NTT,DC=local`) to keep fake accounts organized.
2. **Create Decoy Accounts**: Creates fake user and service accounts inside the Decoy OU. Assigns SPNs to service accounts for Kerberoasting detection.
3. **Copy Files to Network Share**: Copies `inject_decoy.ps1` and creates `decoys.json` in a shared folder (e.g., `C:\Shares\Public` accessible via `\\DC01\Public`).
4. **Configure Group Policy (GPO)**:
   - Creates or updates a GPO (default: `HoneyToken_GPO`) and links it to the target domain or OU.
   - Registers `inject_decoy.ps1` as a Computer Startup Script in SYSVOL (`psscripts.ini`).
   - Updates GPO version numbers in AD and SYSVOL so client computers apply the policy right away.
5. **Inject Credentials on Workstations**:
   - When workstations boot up, `inject_decoy.ps1` runs under the `SYSTEM` account.
   - It reads `decoys.json` from the Network Share.
   - It grants `SeBatchLogonRight` to decoy accounts using Windows LSA APIs (`LsaAddAccountRights`).
   - It creates a Scheduled Task (`HoneyToken_<username>`) set to run at startup as the decoy user. This keeps a background process active, loading NTLM hashes and tickets into LSASS memory.
6. **Save Status Files**: Creates `list.json` to record deployment details and `honey_tokens` (Wazuh CDB list) for security monitoring.

---

### 3. Attack Detection Traps

* **Kerberoasting Trap**:
  - When an attacker scans for SPNs and requests a Kerberos Service Ticket (TGS) for a decoy service (e.g., `MSSQLSvc/sql-decoy.NTT.local:1433`), Windows generates **Event ID 4769**.
  - Wazuh matches the SPN with `honey_tokens` and triggers an alert.

* **Pass-the-Hash (PtH) Trap**:
  - When an attacker dumps LSASS memory on a workstation, finds the decoy account NTLM hash, and tries to log into another machine:
  - Windows generates **Event ID 4624** (Successful Logon) or **Event ID 4625** (Failed Logon).
  - Wazuh matches the decoy username with `honey_tokens` and triggers a Pass-the-Hash alert.

---

### 4. Cleanup Process (`cleanup`)

When you run `python honey_token_gen.py cleanup`:

1. **Clear Network Share Config**: Empties `decoys.json` on the shared folder (`{"decoys": []}`). Workstations automatically stop and delete decoy Scheduled Tasks on their next update.
2. **Remove GPO**: Deletes `HoneyToken_GPO` from Active Directory and SYSVOL.
3. **Delete AD Accounts**: Removes all decoy accounts and deletes the Decoy OU if empty.
4. **Delete Local Files**: Removes shared scripts (`inject_decoy.ps1`, `decoys.json`), tracking record (`list.json`), and Wazuh CDB list (`honey_tokens`).

---

## Project Structure

```
Honey_Token_Generator/
├── honey_token_gen.py    # Main CLI script
├── gpo_ops.py           # GPO management module
├── config.py            # Configuration loader and validator
├── inject_decoy.ps1     # PowerShell script executed on workstations via GPO
├── config.example.json  # Example configuration file
├── requirements.txt     # Python dependencies
├── README.md            # Usage guide and documentation (this file)
└── docs.md              # Detailed code documentation
```

---

## Prerequisites

- **OS**: Windows Server (Domain Controller).
- **Python**: Version 3.10 or higher.
- **PowerShell Modules**: `ActiveDirectory` and `GroupPolicy` (included with Windows Server DC).
- **Permissions**: Administrator / Domain Admin privileges on the Domain Controller.
- **Network Share**: A shared folder on the DC (e.g., `C:\Shares\Public`) with Read access for `Domain Computers` or `Everyone` (UNC path: `\\DC01\Public`).

---

## Installation & Configuration

### 1. Installation

1. Open PowerShell or Command Prompt as Administrator on your Domain Controller.
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Create your configuration file:
   ```bash
   cp config.example.json config.json
   ```

---

### 2. Configuration File (`config.json`)

The `config.json` file has three main sections:

| Section | Description |
| :--- | :--- |
| `domain_settings` | Active Directory settings: domain name, decoy OU, GPO name, and target OU path. |
| `share_settings` | Local folder path and network UNC path for client scripts and configuration. |
| `decoys` | List of decoy accounts: `username`, `password`, `spns` (optional), and `description`. |

---

## Usage Guide

### 1. Deploy Decoys (`deploy`)

Run this command to create decoy accounts, configure GPO, and prepare shared files:

```bash
python honey_token_gen.py deploy --config config.json
```

**What this command does:**
1. Creates the Decoy OU in Active Directory.
2. Creates decoy user accounts and assigns SPNs.
3. Copies `inject_decoy.ps1` and writes `decoys.json` to the shared folder.
4. Creates/configures `HoneyToken_GPO` and sets up the Startup Script.
5. Writes deployment status to `list.json`.
6. Creates the Wazuh CDB list file `honey_tokens`.

---

### 2. Clean Up Decoys (`cleanup`)

Run this command to remove all decoys and GPO settings:

```bash
python honey_token_gen.py cleanup --config config.json
```

**What this command does:**
1. Clears `decoys.json` on the share so workstations remove their scheduled tasks.
2. Deletes `HoneyToken_GPO` from AD and SYSVOL.
3. Deletes all decoy accounts and the Decoy OU.
4. Removes shared files (`inject_decoy.ps1`, `decoys.json`).
5. Deletes local record files (`list.json`, `honey_tokens`).

---

## Output Files

| File | Description |
| :--- | :--- |
| `list.json` | Deployment record containing deployment ID, timestamp, GPO name, and list of deployed decoys. |
| `honey_tokens` | Wazuh CDB list file formatted as `username:description` for security rules. |
| `honey_token_gen.log` | Application log file with detailed execution logs. |