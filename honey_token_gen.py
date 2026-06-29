"""
honey_token_gen.py — Honey Token Generator CLI (GPO & AD Native)

Main entry point for the application. Designed to run natively on the DC.
Commands:
- deploy: Creates local AD accounts and GPOs, copies files to public share
- cleanup: Removes AD accounts, GPOs, and shared files

Usage:
    python honey_token_gen.py deploy --config config.json
    python honey_token_gen.py cleanup --config config.json
"""

import os
import sys
import json
import shutil
import logging
import argparse
import subprocess
from datetime import datetime

from config import load_config
from gpo_ops import create_or_configure_gpo, remove_gpo

# --- Constants ---
LIST_FILE = "list.json"
CDB_FILE = "honey_tokens"
LOG_FILE = "honey_token_gen.log"
CLIENT_SCRIPT_NAME = "inject_decoy.ps1"
CONFIG_SHARE_NAME = "decoys.json"


def setup_logging() -> None:
    """Configures logging to output to both console and a log file."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Console handler — INFO level
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    console_handler.setFormatter(console_format)

    # File handler — DEBUG level
    file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    file_handler.setFormatter(file_format)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


logger = logging.getLogger("honey_token_gen")


def _run_ps_cmd(cmd: str) -> tuple[int, str, str]:
    """Runs a PowerShell command locally on the Domain Controller."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def parse_dn(dn: str) -> tuple[str, str]:
    """Parses a DN (like OU=Decoys,DC=NTT,DC=local) into (Name, ParentPath)."""
    parts = dn.split(",")
    name = parts[0].split("=")[1]
    parent = ",".join(parts[1:])
    return name, parent


def cmd_deploy(args: argparse.Namespace) -> None:
    """Orchestrates the GPO-based deployment workflow."""
    config_path = args.config

    logger.info("=" * 60)
    logger.info("DEPLOY started (GPO & AD Native)")
    logger.info("=" * 60)

    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    ds = config["domain_settings"]
    ss = config["share_settings"]
    decoys_pool = config["decoys"]

    # --- Check if a deployment already exists ---
    if os.path.exists(LIST_FILE):
        logger.error(
            f"Deployment record '{LIST_FILE}' already exists. "
            f"Please run 'cleanup' first before deploying again."
        )
        sys.exit(1)

    # --- 1. Create Decoy OU in Active Directory ---
    ou_name, ou_parent = parse_dn(ds["decoy_ou"])
    logger.info(f"Ensuring Decoy OU exists: '{ds['decoy_ou']}'...")
    
    ou_check_cmd = f"Get-ADOrganizationalUnit -Identity '{ds['decoy_ou']}' -ErrorAction SilentlyContinue"
    code, stdout, stderr = _run_ps_cmd(ou_check_cmd)
    
    if code != 0:
        # Create OU
        create_ou_cmd = f"New-ADOrganizationalUnit -Name '{ou_name}' -Path '{ou_parent}'"
        code, stdout, stderr = _run_ps_cmd(create_ou_cmd)
        if code != 0:
            logger.error(f"Failed to create Decoy OU: {stderr}")
            sys.exit(1)
        logger.info("Decoy OU created successfully.")
    else:
        logger.info("Decoy OU already exists.")

    # --- 2. Deploy AD User Accounts ---
    stats = {"ad_success": 0, "ad_fail": 0}
    ad_created = set()

    for decoy in decoys_pool:
        username = decoy["username"]
        password = decoy["password"]
        description = decoy["description"]
        spns = decoy.get("spns", [])

        logger.info(f"Deploying AD account '{username}'...")
        
        # Check if user exists
        user_check_cmd = f"Get-ADUser -Filter \"SamAccountName -eq '{username}'\" -ErrorAction SilentlyContinue"
        code, stdout, stderr = _run_ps_cmd(user_check_cmd)
        
        if code != 0 or not stdout:
            # Create user
            create_user_cmd = (
                f"$secPass = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
                f"New-ADUser -Name '{username}' -SamAccountName '{username}' -AccountPassword $secPass "
                f"-Enabled $true -Path '{ds['decoy_ou']}' -Description '{description}'"
            )
            code, stdout, stderr = _run_ps_cmd(create_user_cmd)
            if code != 0:
                logger.error(f"Failed to create decoy account '{username}': {stderr}")
                stats["ad_fail"] += 1
                continue
            logger.info(f"Decoy account '{username}' created successfully.")
        else:
            # Update description if user exists
            update_user_cmd = f"Set-ADUser -Identity '{username}' -Description '{description}'"
            _run_ps_cmd(update_user_cmd)
            logger.info(f"Decoy account '{username}' already exists. Updated description.")

        # Assign SPNs if any
        if spns:
            spn_list = ",".join([f"'{s}'" for s in spns])
            spn_cmd = f"Set-ADUser -Identity '{username}' -ServicePrincipalNames @{{Replace=@({spn_list})}}"
            code, stdout, stderr = _run_ps_cmd(spn_cmd)
            if code != 0:
                logger.warning(f"Failed to assign SPNs to '{username}': {stderr}")
            else:
                logger.info(f"Assigned SPNs to '{username}': {spns}")
        else:
            # Clear SPNs
            _run_ps_cmd(f"Set-ADUser -Identity '{username}' -ServicePrincipalNames $null")

        stats["ad_success"] += 1
        ad_created.add(username)

    # --- 3. Copy injection script and write decoys.json to Custom Public Share ---
    local_share_path = ss["local_path"]
    logger.info(f"Ensuring local share directory exists: '{local_share_path}'...")
    os.makedirs(local_share_path, exist_ok=True)

    # Copy inject_decoy.ps1 from repository to share
    repo_script_path = os.path.join(os.path.dirname(__file__), CLIENT_SCRIPT_NAME)
    dest_script_path = os.path.join(local_share_path, CLIENT_SCRIPT_NAME)
    
    if os.path.exists(repo_script_path):
        logger.info(f"Copying '{CLIENT_SCRIPT_NAME}' to '{local_share_path}'...")
        shutil.copy(repo_script_path, dest_script_path)
    else:
        logger.error(f"Client script '{CLIENT_SCRIPT_NAME}' not found in repo directory!")
        sys.exit(1)

    # Filter out successfully created decoys and save to decoys.json on share
    active_decoys = [d for d in decoys_pool if d["username"] in ad_created]
    decoys_json_data = {
        "decoys": [
            {
                "username": d["username"],
                "password": d["password"]
            } for d in active_decoys
        ]
    }
    
    dest_json_path = os.path.join(local_share_path, CONFIG_SHARE_NAME)
    logger.info(f"Writing deployment configuration to '{dest_json_path}'...")
    try:
        with open(dest_json_path, "w") as f:
            json.dump(decoys_json_data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write configuration to share: {e}")
        sys.exit(1)

    # --- 4. Configure GPO ---
    network_script_path = f"{ss['network_path']}\\{CLIENT_SCRIPT_NAME}"
    network_config_path = f"{ss['network_path']}\\{CONFIG_SHARE_NAME}"
    
    # Format script execution command
    # E.g., \\DC01\Public\inject_decoy.ps1 -DecoyConfigPath \\DC01\Public\decoys.json
    full_script_path = f"powershell.exe"
    # Escaping arguments for the registry scripts.ini
    full_script_args = f"-NonInteractive -NoProfile -ExecutionPolicy Bypass -File {network_script_path} -DecoyConfigPath {network_config_path}"
    
    try:
        create_or_configure_gpo(
            domain_name=ds["domain_name"],
            decoy_ou_dn=ds["decoy_ou"],
            gpo_name=ds["gpo_name"],
            target_ou_dn=ds["target_ou_dn"],
            network_script_path=network_script_path
        )
    except Exception as e:
        logger.error(f"Failed to create/configure GPO: {e}")
        sys.exit(1)

    # --- 5. Write local deployment record (list.json) ---
    now = datetime.now()
    output_record = {
        "deployment_id": now.strftime("%Y%m%d_%H%M%S"),
        "domain": ds["domain_name"],
        "gpo_name": ds["gpo_name"],
        "deployed_at": now.isoformat(),
        "share_local_path": local_share_path,
        "decoys": [
            {
                "username": d["username"],
                "spns": d.get("spns", []),
                "description": d["description"]
            } for d in active_decoys
        ]
    }

    try:
        with open(LIST_FILE, "w") as f:
            json.dump(output_record, f, indent=2)
        logger.info(f"Deployment record written to local '{LIST_FILE}'")
    except Exception as e:
        logger.error(f"Failed to write deployment record: {e}")

    # --- 6. Write local CDB list for Wazuh ---
    try:
        seen = set()
        cdb_lines = []
        for decoy in active_decoys:
            if decoy["username"] not in seen:
                seen.add(decoy["username"])
                cdb_lines.append(f"{decoy['username']}:{decoy['description']}")

        with open(CDB_FILE, "w") as f:
            f.write("\n".join(cdb_lines) + "\n")
        logger.info(f"Wazuh CDB list written to local '{CDB_FILE}'")
    except Exception as e:
        logger.error(f"Failed to write Wazuh CDB list: {e}")

    # --- Print Summary ---
    logger.info("=" * 60)
    logger.info("DEPLOY SUMMARY")
    logger.info(f"  AD accounts deployed:       {stats['ad_success']}")
    logger.info(f"  AD accounts failed:         {stats['ad_fail']}")
    logger.info(f"  Total decoys configured:    {len(active_decoys)}")
    logger.info(f"  Workstation config share:   {network_config_path}")
    logger.info("=" * 60)


def cmd_cleanup(args: argparse.Namespace) -> None:
    """Orchestrates the GPO-based cleanup workflow."""
    config_path = args.config

    logger.info("=" * 60)
    logger.info("CLEANUP started (GPO & AD Native)")
    logger.info("=" * 60)

    if not os.path.exists(LIST_FILE):
        logger.warning(f"Deployment record '{LIST_FILE}' not found. Nothing to clean up.")
        sys.exit(1)

    try:
        with open(LIST_FILE, "r") as f:
            list_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse deployment record '{LIST_FILE}': {e}")
        sys.exit(1)

    deployed_decoys = list_data.get("decoys", [])
    local_share_path = list_data.get("share_local_path", "C:\\Shares\\Public")
    gpo_name = list_data.get("gpo_name", "HoneyToken_GPO")

    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    ds = config["domain_settings"]

    # --- 1. Empty/Remove decoys.json on Share first ---
    # This signals workstations to immediately delete their scheduled tasks on next GPO run/startup
    json_share_path = os.path.join(local_share_path, CONFIG_SHARE_NAME)
    if os.path.exists(json_share_path):
        logger.info(f"Clearing configuration in '{json_share_path}' to trigger workstation cleanup...")
        try:
            # Write empty decoys list to trigger automatic cleanup on endpoints
            with open(json_share_path, "w") as f:
                json.dump({"decoys": []}, f, indent=2)
            logger.info("Workstation config share cleared.")
        except Exception as e:
            logger.warning(f"Failed to clear configuration share: {e}")

    # --- 2. Remove GPO ---
    try:
        remove_gpo(gpo_name)
    except Exception as e:
        logger.error(f"Failed to remove GPO '{gpo_name}': {e}")

    # --- 3. Remove AD Accounts ---
    stats = {"ad_success": 0, "ad_fail": 0}
    for decoy in deployed_decoys:
        username = decoy["username"]
        logger.info(f"Removing decoy AD account '{username}'...")
        remove_user_cmd = f"Remove-ADUser -Identity '{username}' -Confirm:$false -ErrorAction SilentlyContinue"
        code, stdout, stderr = _run_ps_cmd(remove_user_cmd)
        if code != 0:
            logger.warning(f"Failed to remove AD account '{username}': {stderr}")
            stats["ad_fail"] += 1
        else:
            logger.info(f"Decoy account '{username}' deleted successfully.")
            stats["ad_success"] += 1

    # --- 4. Remove Decoy OU if empty ---
    logger.info(f"Checking if Decoy OU '{ds['decoy_ou']}' is empty...")
    ou_check_children = f"Get-ADUser -Filter * -SearchBase '{ds['decoy_ou']}' -ErrorAction SilentlyContinue"
    code, stdout, stderr = _run_ps_cmd(ou_check_children)
    
    if code == 0 and not stdout:
        logger.info(f"Decoy OU is empty. Deleting '{ds['decoy_ou']}'...")
        remove_ou_cmd = f"Remove-ADOrganizationalUnit -Identity '{ds['decoy_ou']}' -Confirm:$false -ErrorAction SilentlyContinue"
        code, stdout, stderr = _run_ps_cmd(remove_ou_cmd)
        if code != 0:
            logger.warning(f"Failed to delete Decoy OU: {stderr}")
        else:
            logger.info("Decoy OU deleted successfully.")
    else:
        logger.warning("Decoy OU is not empty or failed to check. Skipping OU deletion.")

    # --- 5. Clean up local files ---
    # Delete script and config from public share
    for filename in [CLIENT_SCRIPT_NAME, CONFIG_SHARE_NAME]:
        filepath = os.path.join(local_share_path, filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                logger.info(f"Deleted shared file: {filepath}")
            except Exception as e:
                logger.warning(f"Failed to delete shared file '{filepath}': {e}")

    # Delete local record files
    for filename in [LIST_FILE, CDB_FILE]:
        if os.path.exists(filename):
            try:
                os.remove(filename)
                logger.info(f"Deleted local file: {filename}")
            except Exception as e:
                logger.warning(f"Failed to delete local file '{filename}': {e}")

    logger.info("=" * 60)
    logger.info("CLEANUP SUMMARY")
    logger.info(f"  AD accounts deleted:        {stats['ad_success']}")
    logger.info(f"  AD accounts failed:         {stats['ad_fail']}")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        prog="honey_token_gen",
        description="GPO-Based Honey Token Generator for AD Environment (Local DC Orchestration).",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Deploy subcommand
    deploy_parser = subparsers.add_parser("deploy", help="Deploy decoys locally on DC and configure GPO")
    deploy_parser.add_argument("--config", default="config.json", help="Path to config file")

    # Cleanup subcommand
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up decoys and GPOs from AD")
    cleanup_parser.add_argument("--config", default="config.json", help="Path to config file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging()

    if args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)


if __name__ == "__main__":
    main()
