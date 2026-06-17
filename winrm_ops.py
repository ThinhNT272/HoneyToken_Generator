"""
winrm_ops.py — WinRM Endpoint Operations

Handles all interactions with Windows workstations via WinRM:
- Establishing WinRM sessions
- Injecting honey-token cached credentials via scheduled tasks
- Removing honey-token cached credentials
- Verifying credential injection

Note: Direct cmdkey execution over WinRM fails because WinRM runs
in a non-interactive Network Logon Session (Type 3), and Windows
blocks cmdkey from saving credentials in that context. The solution
wraps cmdkey inside a transient Windows Scheduled Task running under
the SYSTEM account. Because Scheduled Tasks are executed locally by
the OS itself, Windows treats it as a trusted session, allowing
credentials to be saved to the workstation's Credential Manager.
"""

import logging
import winrm

logger = logging.getLogger("honey_token_gen.winrm")

# Timeout (seconds) to wait for the scheduled task to complete
TASK_WAIT_SECONDS = 5


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


def _build_target(username: str, domain: str) -> str:
    """Builds a unique cmdkey target for a specific decoy.

    Each decoy gets its own unique target to prevent overwrites
    when multiple decoys are injected on the same host.

    Args:
        username: The decoy username (e.g., 'sql-decoy').
        domain: The domain name (e.g., 'NTT.local').

    Returns:
        A unique target string (e.g., 'sql-decoy.NTT.local').
    """
    return f"{username}.{domain}"


def inject_credential_decoy(session: winrm.Session, domain: str,
                            username: str, password: str,
                            dry_run: bool = False) -> None:
    """Injects a honey-token cached credential on the endpoint.

    Creates a transient Windows Scheduled Task that runs cmdkey.exe
    under the SYSTEM account to bypass the WinRM non-interactive session
    restriction. The task runs immediately and is cleaned up afterward.

    Args:
        session: Active WinRM session.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        password: Honey-token password.
        dry_run: If True, simulate without modifying the endpoint.

    Raises:
        RuntimeError: If the scheduled task fails to inject the credential.
    """
    target = _build_target(username, domain)
    user_principal = f"{domain}\\{username}"
    task_name = f"HoneyToken_Inject_{username}"

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would inject credential via scheduled task: "
            f"cmdkey /add:{target} /user:{user_principal} /pass:****"
        )
        return

    logger.info(f"Injecting credential for '{user_principal}' with target '{target}'")

    # PowerShell script that:
    # 1. Creates a scheduled task running cmdkey as SYSTEM
    # 2. Runs it immediately
    # 3. Waits for completion
    # 4. Checks the result
    # 5. Cleans up the task
    ps_script = f"""
$ErrorActionPreference = 'Stop'
$taskName = '{task_name}'
$cmdkeyArgs = '/add:{target} /user:{user_principal} /pass:{password}'

try {{
    # Create the scheduled task action
    $action = New-ScheduledTaskAction -Execute 'cmdkey.exe' -Argument $cmdkeyArgs

    # Run as SYSTEM to bypass non-interactive session restriction
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    # Register and start the task
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    # Wait for the task to complete
    Start-Sleep -Seconds {TASK_WAIT_SECONDS}

    # Check the result
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    $exitCode = 0
    if ($taskInfo) {{
        $exitCode = $taskInfo.LastTaskResult
    }}

    # Clean up the scheduled task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    if ($exitCode -eq 0) {{
        Write-Output "SUCCESS: Credential injected for {user_principal}"
    }} else {{
        Write-Output "FAILED: cmdkey exited with code $exitCode"
        exit 1
    }}
}} catch {{
    # Clean up on error
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Error "Failed to inject credential: $_"
    exit 1
}}
"""

    status, stdout, stderr = _run_ps(session, ps_script)

    if status != 0:
        raise RuntimeError(
            f"Credential injection failed (exit code {status}). "
            f"stdout: {stdout}. stderr: {stderr}"
        )

    logger.info(f"Credential injected successfully. Output: {stdout}")


def remove_credential_decoy(session: winrm.Session, domain: str,
                            username: str, dry_run: bool = False) -> None:
    """Removes a specific honey-token cached credential from the endpoint.

    Uses the same scheduled task approach as injection to ensure the
    removal runs in a trusted session context.

    Args:
        session: Active WinRM session.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        dry_run: If True, simulate without modifying the endpoint.
    """
    target = _build_target(username, domain)
    task_name = f"HoneyToken_Remove_{username}"

    if dry_run:
        logger.info(f"[DRY-RUN] Would remove credential via scheduled task: cmdkey /delete:{target}")
        return

    logger.info(f"Removing credential with target '{target}'")

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$taskName = '{task_name}'

try {{
    $action = New-ScheduledTaskAction -Execute 'cmdkey.exe' -Argument '/delete:{target}'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds {TASK_WAIT_SECONDS}

    # Clean up the scheduled task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    Write-Output "SUCCESS: Credential removed for target {target}"
}} catch {{
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "WARNING: Removal may have failed (credential might already be removed): $_"
}}
"""

    status, stdout, stderr = _run_ps(session, ps_script)

    if status != 0:
        # Non-zero is acceptable — credential might already be removed (idempotent)
        logger.warning(
            f"Credential removal returned exit code {status} for target '{target}'. "
            f"The credential may already have been removed. stderr: {stderr}"
        )
    else:
        logger.info(f"Credential removal completed. Output: {stdout}")
