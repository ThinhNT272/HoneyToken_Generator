"""
gpo_ops.py — GPO Orchestration Module

Manages Active Directory Group Policy Objects (GPOs) locally on the DC:
- Checking, creating, and linking GPOs
- Registering a custom network script as a GPO Startup Script
- Synchronizing GPO version numbers (GPT.ini and AD versionNumber)
- Removing GPOs during cleanup
"""

import os
import re
import logging
import subprocess

logger = logging.getLogger("honey_token_gen.gpo")


def _run_ps_cmd(cmd: str) -> tuple[int, str, str]:
    """Runs a PowerShell command locally on the Domain Controller."""
    logger.debug(f"Executing local PowerShell: {cmd}")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def create_or_configure_gpo(domain_name: str, decoy_ou_dn: str, gpo_name: str, target_ou_dn: str, network_script_path: str) -> None:
    """Creates a GPO, links it, and configures the Startup Script.

    Args:
        domain_name: Domain DNS name (e.g., 'NTT.local').
        decoy_ou_dn: DN of the Decoy OU (not used for link, but logged).
        gpo_name: Name of the GPO (e.g., 'HoneyToken_GPO').
        target_ou_dn: DN of the OU to link the GPO to (e.g., 'DC=NTT,DC=local').
        network_script_path: Network path to the script (e.g., '\\\\DC01\\Public\\inject_decoy.ps1').
    """
    logger.info(f"Checking for GPO '{gpo_name}'...")

    # 1. Check if GPO exists
    code, stdout, stderr = _run_ps_cmd(f"Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue")
    
    if code != 0:
        logger.info(f"GPO '{gpo_name}' not found. Creating it...")
        code, stdout, stderr = _run_ps_cmd(f"New-GPO -Name '{gpo_name}'")
        if code != 0:
            raise RuntimeError(f"Failed to create GPO '{gpo_name}': {stderr}")
        logger.info(f"GPO '{gpo_name}' created successfully.")

    # 2. Get GPO GUID
    code, stdout, stderr = _run_ps_cmd(f"(Get-GPO -Name '{gpo_name}').Id.Guid")
    if code != 0 or not stdout:
        raise RuntimeError(f"Failed to get GPO GUID for '{gpo_name}': {stderr}")
    gpo_guid = stdout
    logger.info(f"GPO GUID: {gpo_guid}")

    # 3. Link GPO to target OU/Domain
    logger.info(f"Linking GPO '{gpo_name}' to '{target_ou_dn}'...")
    _run_ps_cmd(f"New-GPLink -Name '{gpo_name}' -Target '{target_ou_dn}' -LinkEnabled Yes -ErrorAction SilentlyContinue")

    # 4. Write script configuration directly inside GPO folder in SYSVOL
    # Path: C:\Windows\SYSVOL\sysvol\<domain>\Policies\{GUID}\Machine\Scripts\
    sysvol_gpo_path = f"C:\\Windows\\SYSVOL\\sysvol\\{domain_name}\\Policies\\{{{gpo_guid}}}"
    scripts_dir = os.path.join(sysvol_gpo_path, "Machine", "Scripts")
    
    # Ensure directories exist
    os.makedirs(scripts_dir, exist_ok=True)

    # psscripts.ini configuration (must be UTF-16LE with BOM)
    psscripts_ini_path = os.path.join(scripts_dir, "psscripts.ini")
    logger.info(f"Registering startup script in GPO psscripts.ini...")
    
    psscripts_content = f"""[ScriptsConfig]
EndExecutePSFirst=true
[Startup]
0CmdLine={network_script_path}
0Parameters=
"""
    # Writing in UTF-16LE with BOM
    with open(psscripts_ini_path, "w", encoding="utf-16") as f:
        f.write(psscripts_content)

    # 5. Synchronize GPO Version (GPT.ini and AD versionNumber)
    # This notifies clients that a computer policy update is available
    gpt_ini_path = os.path.join(sysvol_gpo_path, "GPT.ini")
    
    current_version = 0
    if os.path.exists(gpt_ini_path):
        try:
            with open(gpt_ini_path, "r", encoding="utf-8", errors="ignore") as f:
                gpt_content = f.read()
            match = re.search(r"Version=(\d+)", gpt_content, re.IGNORECASE)
            if match:
                current_version = int(match.group(1))
        except Exception as e:
            logger.warning(f"Failed to read current GPO version from GPT.ini: {e}")

    # Increment computer configuration version (adds 65536 to the version number)
    # Using 131072 (Computer version 2, User version 0) as a robust default
    new_version = max(current_version + 65536, 131072)
    logger.info(f"Updating GPO version to {new_version}...")

    # Write new GPT.ini
    gpt_content = f"""[General]
Version={new_version}
"""
    with open(gpt_ini_path, "w", encoding="utf-8") as f:
        f.write(gpt_content)

    # Update versionNumber in AD
    domain_dn = ",".join([f"DC={part}" for part in domain_name.split(".")])
    gpo_ad_dn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{domain_dn}"
    
    # Update GPO versionNumber in AD
    code, stdout, stderr = _run_ps_cmd(
        f"Set-ADObject -Identity '{gpo_ad_dn}' -Replace @{{versionNumber={new_version}}}"
    )
    if code != 0:
        raise RuntimeError(f"Failed to update GPO versionNumber in AD: {stderr}")
    logger.info(f"GPO versionNumber updated to {new_version}.")

    # Configure the Scripts CSE extension GUIDs so Windows clients process the startup script.
    # Use a PowerShell variable ($ext) to hold the GUID string, avoiding brace-parsing
    # conflicts between the GUID curly braces and PowerShell's hashtable @{} syntax.
    cse_guid_str = (
        "[{962A0534-0E65-11D2-824F-00105A14F938}{42B5F986-6536-11D2-AE5A-0000F87571E3}]"
        "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{42B5F986-6536-11D2-AE5A-0000F87571E3}]"
    )
    code, stdout, stderr = _run_ps_cmd(
        f"$ext = '{cse_guid_str}'; "
        f"Set-ADObject -Identity '{gpo_ad_dn}' -Replace @{{gPCMachineExtensionNames=$ext}}"
    )
    if code != 0:
        raise RuntimeError(f"Failed to set gPCMachineExtensionNames on GPO: {stderr}")
    logger.info("GPO Extension CSE GUIDs successfully updated in Active Directory.")


def remove_gpo(gpo_name: str) -> None:
    """Removes a GPO from AD. This also deletes its files in SYSVOL.

    Args:
        gpo_name: Name of the GPO to delete.
    """
    logger.info(f"Removing GPO '{gpo_name}'...")
    code, stdout, stderr = _run_ps_cmd(f"Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue")
    if code == 0:
        code, stdout, stderr = _run_ps_cmd(f"Remove-GPO -Name '{gpo_name}' -Confirm:$false")
        if code != 0:
            logger.error(f"Failed to delete GPO '{gpo_name}': {stderr}")
        else:
            logger.info(f"GPO '{gpo_name}' deleted successfully.")
    else:
        logger.info(f"GPO '{gpo_name}' does not exist. Skipping.")
