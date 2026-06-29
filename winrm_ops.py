"""
winrm_ops.py — WinRM Endpoint Operations

Handles all interactions with Windows workstations via WinRM:
- Establishing WinRM sessions
- Injecting honey-token credentials as separate logon sessions
- Removing honey-token credentials by killing their holder processes

Credential Injection Mechanism:
    Each honey-token credential is injected by launching a hidden
    background PowerShell process on the endpoint using
    Start-Process -Credential. This creates a real Interactive
    logon session (Type 2) in LSASS, causing each decoy to appear
    as a separate session with NTLM/SHA1 hashes when dumped by
    tools like Mimikatz — indistinguishable from genuine cached
    credentials.

    The PID of each holder process is stored in a registry key
    (HKLM:\SOFTWARE\HoneyTokens\<username>) so the cleanup
    command can find and kill them later.
"""

import logging
import winrm

logger = logging.getLogger("honey_token_gen.winrm")


def get_winrm_session(ip: str, username: str, password: str,
                      transport: str = "ntlm") -> winrm.Session:
    """Creates a WinRM session for a given endpoint.

    Connects via HTTP on port 5985 (standard WinRM HTTP port).

    Args:
        ip: IP address of the target workstation.
        username: Admin username for WinRM authentication.
        password: Admin password.
        transport: WinRM transport mechanism (default: 'ntlm').

    Returns:
        A winrm.Session object ready for command execution.
    """
    endpoint = f"http://{ip}:5985/wsman"
    logger.info(f"Creating WinRM session to {ip} (transport: {transport})")

    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport,
    )
    return session


def _run_ps(session: winrm.Session, script: str) -> tuple:
    """Executes a PowerShell script on the remote session.

    Args:
        session: The WinRM session.
        script: PowerShell script string to execute.

    Returns:
        Tuple of (status_code, stdout, stderr).
    """
    result = session.run_ps(script)
    stdout = result.std_out.decode("utf-8", errors="ignore").strip()
    stderr = result.std_err.decode("utf-8", errors="ignore").strip()
    return result.status_code, stdout, stderr


def inject_credential_decoy(session: winrm.Session, domain: str,
                            username: str, password: str,
                            dry_run: bool = False) -> None:
    """Injects a honey-token credential as a real logon session on the endpoint.

    Launches a hidden background PowerShell process running under the
    decoy user's credentials via Start-Process -Credential. This causes
    Windows to create a genuine Interactive logon session (Type 2) in
    LSASS, complete with NTLM and SHA1 hashes.

    The holder process PID is saved to the registry at
    HKLM:\SOFTWARE\HoneyTokens\<username> for later cleanup.

    Args:
        session: Active WinRM session to the endpoint.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        password: Honey-token password.
        dry_run: If True, simulate without modifying the endpoint.

    Raises:
        RuntimeError: If the credential injection fails.
    """
    user_principal = f"{domain}\\{username}"

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would inject credential for '{user_principal}' "
            f"via Start-Process -Credential"
        )
        return

    logger.info(f"Injecting credential for '{user_principal}'")

    # PowerShell script that:
    # 1. Creates a PSCredential object for the decoy user
    # 2. Launches a hidden background process under that credential
    #    (creates a Type 2 Interactive logon session in LSASS)
    # 3. Saves the holder process PID to the registry for cleanup
    ps_script = f"""
$ErrorActionPreference = 'Stop'

try {{
    # Build credential object for the decoy user
    $secPass = ConvertTo-SecureString '{password}' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('{user_principal}', $secPass)

    # Launch a hidden background process under the decoy credential.
    # This creates a real Interactive logon session (Type 2) in LSASS.
    # The process sleeps indefinitely to keep the session alive.
    $proc = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList '-WindowStyle Hidden -NoProfile -Command "while(1){{Start-Sleep 3600}}"' `
        -Credential $cred `
        -PassThru -WindowStyle Hidden

    # Save the PID to registry so cleanup can find and kill it later
    $regPath = 'HKLM:\\SOFTWARE\\HoneyTokens'
    if (-not (Test-Path $regPath)) {{
        New-Item -Path $regPath -Force | Out-Null
    }}
    Set-ItemProperty -Path $regPath -Name '{username}' -Value $proc.Id -Type DWord

    Write-Output "SUCCESS: Credential injected for {user_principal} (PID: $($proc.Id))"
}} catch {{
    Write-Error "Failed to inject credential for {user_principal}: $_"
    exit 1
}}
"""

    status, stdout, stderr = _run_ps(session, ps_script)

    if status != 0:
        raise RuntimeError(
            f"Credential injection failed for '{user_principal}' "
            f"(exit code {status}). stdout: {stdout}. stderr: {stderr}"
        )

    logger.info(f"Credential injected successfully. Output: {stdout}")


def remove_credential_decoy(session: winrm.Session, domain: str,
                            username: str, dry_run: bool = False) -> None:
    """Removes a honey-token credential by killing its holder process.

    Reads the holder process PID from the registry at
    HKLM:\SOFTWARE\HoneyTokens\<username>, kills the process
    (which destroys the logon session and purges credentials from
    LSASS), then removes the registry entry.

    Args:
        session: Active WinRM session to the endpoint.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        dry_run: If True, simulate without modifying the endpoint.
    """
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would remove credential for '{domain}\\{username}' "
            f"by killing holder process"
        )
        return

    logger.info(f"Removing credential for '{domain}\\{username}'")

    # PowerShell script that:
    # 1. Reads the holder process PID from registry
    # 2. Kills the process (destroys the logon session)
    # 3. Removes the registry entry
    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$regPath = 'HKLM:\\SOFTWARE\\HoneyTokens'

# Read the PID from registry
$pid = Get-ItemProperty -Path $regPath -Name '{username}' -ErrorAction SilentlyContinue

if ($pid) {{
    $processId = $pid.'{username}'

    # Kill the holder process to destroy the logon session
    $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($proc) {{
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        Write-Output "SUCCESS: Killed holder process (PID: $processId) for '{username}'"
    }} else {{
        Write-Output "WARNING: Holder process (PID: $processId) for '{username}' not found (may have already exited)"
    }}

    # Remove the registry entry
    Remove-ItemProperty -Path $regPath -Name '{username}' -ErrorAction SilentlyContinue
}} else {{
    Write-Output "WARNING: No registry entry found for '{username}' (credential may have already been removed)"
}}

# Clean up registry key if no more entries remain
$remaining = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
if ($remaining) {{
    $props = $remaining.PSObject.Properties | Where-Object {{ $_.Name -notlike 'PS*' }}
    if (-not $props) {{
        Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
    }}
}}
"""

    status, stdout, stderr = _run_ps(session, ps_script)

    if status != 0:
        # Non-zero is acceptable — credential might already be removed (idempotent)
        logger.warning(
            f"Credential removal returned exit code {status} for '{username}'. "
            f"The credential may already have been removed. stderr: {stderr}"
        )
    else:
        logger.info(f"Credential removal completed. Output: {stdout}")
