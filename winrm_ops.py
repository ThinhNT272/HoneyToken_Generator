"""
winrm_ops.py — WinRM Endpoint Operations

Handles all interactions with Windows workstations via WinRM:
- Establishing WinRM sessions
- Injecting honey-token credentials as separate logon sessions
- Removing honey-token credentials by stopping and unregistering tasks

Credential Injection Mechanism:
    Each honey-token credential is injected by creating a Windows
    Scheduled Task that runs under the decoy user's credentials.
    When the task executes, Windows creates a real Batch logon
    session (Type 4) in LSASS, causing each decoy to appear as
    a separate session with NTLM/SHA1 hashes when dumped by tools
    like Mimikatz — indistinguishable from genuine cached credentials.

    Each task is named 'HoneyToken_<username>' for deterministic
    identification during cleanup.
"""

import logging
import winrm

logger = logging.getLogger("honey_token_gen.winrm")

# Prefix for all honey-token scheduled task names
TASK_PREFIX = "HoneyToken_"


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

    Creates a Windows Scheduled Task that runs a hidden PowerShell
    process under the decoy user's credentials. When the task starts,
    Windows creates a Batch logon session (Type 4) in LSASS, complete
    with NTLM and SHA1 hashes — each decoy gets its own session.

    The task is named 'HoneyToken_<username>' for deterministic cleanup.

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
    task_name = f"{TASK_PREFIX}{username}"

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would inject credential for '{user_principal}' "
            f"via Scheduled Task '{task_name}'"
        )
        return

    logger.info(f"Injecting credential for '{user_principal}'")

    # PowerShell script that:
    # 1. Grants the decoy user SeBatchLogonRight using Local Security Authority (LSA) Win32 APIs
    # 2. Removes any existing task with the same name (idempotent)
    # 3. Creates a Scheduled Task that runs as the decoy user
    #    (creates a Type 4 Batch logon session in LSASS with NTLM/SHA1 hashes)
    # 4. Starts the task immediately
    # 5. Verifies the task is running
    ps_script = f"""
$ErrorActionPreference = 'Stop'
$CSharp = @"
using System;using System.Runtime.InteropServices;
public class Ls {{
[DllImport("advapi32.dll")]public static extern uint LsaOpenPolicy(IntPtr s,IntPtr o,uint a,out IntPtr h);
[DllImport("advapi32.dll")]public static extern uint LsaAddAccountRights(IntPtr h,IntPtr sid,L_S[] r,uint c);
[DllImport("advapi32.dll")]public static extern uint LsaClose(IntPtr h);
[StructLayout(LayoutKind.Sequential)]public struct L_S {{public ushort l;public ushort m;public IntPtr b;}}
}}
"@
if (-not ("Ls" -as [type])) {{Add-Type -TypeDefinition $CSharp}}
function G-B($n) {{
$a=New-Object System.Security.Principal.NTAccount($n)
$s=$a.Translate([System.Security.Principal.SecurityIdentifier])
$b=New-Object byte[] $s.BinaryLength
$s.GetBinaryForm($b,0)
$p=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($s.BinaryLength)
[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,$s.BinaryLength)
$h=[IntPtr]::Zero
[Ls]::LsaOpenPolicy([IntPtr]::Zero,[IntPtr]::Zero,0x000F0811,[ref]$h)
$r=New-Object Ls+L_S
$r.b=[System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("SeBatchLogonRight")
$r.l=[ushort]32
$r.m=[ushort]34
[void][Ls]::LsaAddAccountRights($h,$p,[Ls+L_S[]]@($r),1)
[void][Ls]::LsaClose($h)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($p)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($r.b)
}}
try {{
$taskName = '{task_name}'
$runAsUser = '{user_principal}'
G-B $runAsUser
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -Command "while(1){{Start-Sleep 3600}}"'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -User $runAsUser -Password '{password}' -RunLevel Limited -ErrorAction Stop | Out-Null
Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.State -eq 'Running') {{
Write-Output "SUCCESS: Credential injected for $runAsUser (Task: $taskName, State: Running)"
}} else {{
Write-Output "WARNING: Task created but state is '$($task.State)' for $runAsUser"
}}
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
    """Removes a honey-token credential by stopping and unregistering its task.

    Stops the Scheduled Task 'HoneyToken_<username>' (which kills
    the holder process and destroys the logon session, purging
    credentials from LSASS), then unregisters the task entirely.

    Args:
        session: Active WinRM session to the endpoint.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        dry_run: If True, simulate without modifying the endpoint.
    """
    task_name = f"{TASK_PREFIX}{username}"

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would remove credential for '{domain}\\{username}' "
            f"by stopping task '{task_name}'"
        )
        return

    logger.info(f"Removing credential for '{domain}\\{username}'")

    # PowerShell script that:
    # 1. Stops the scheduled task (kills the process, destroys logon session)
    # 2. Unregisters the task entirely
    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$taskName = '{task_name}'

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($task) {{
    # Stop the task (kills the holder process and destroys the logon session)
    if ($task.State -eq 'Running') {{
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }}

    # Unregister the task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "SUCCESS: Removed task '$taskName' for '{username}'"
}} else {{
    Write-Output "WARNING: Task '$taskName' not found (credential may have already been removed)"
}}
"""

    status, stdout, stderr = _run_ps(session, ps_script)

    if status != 0:
        # Non-zero is acceptable — task might already be removed (idempotent)
        logger.warning(
            f"Credential removal returned exit code {status} for '{username}'. "
            f"The credential may already have been removed. stderr: {stderr}"
        )
    else:
        logger.info(f"Credential removal completed. Output: {stdout}")
