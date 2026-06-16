"""
winrm_ops.py — WinRM Endpoint Operations

Handles all interactions with Windows workstations via WinRM:
- Establishing WinRM sessions
- Injecting honey-token cached credentials (cmdkey)
- Removing honey-token cached credentials
- Verifying credential injection
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


def _run_cmd(session: winrm.Session, command: str, args: tuple = ()) -> tuple:
    """Executes a command via cmd.exe on the remote session.

    Args:
        session: The WinRM session.
        command: Command to execute.
        args: Command arguments as a tuple of strings.

    Returns:
        Tuple of (status_code, stdout, stderr).
    """
    result = session.run_cmd(command, args)
    stdout = result.std_out.decode("utf-8", errors="ignore").strip()
    stderr = result.std_err.decode("utf-8", errors="ignore").strip()
    return result.status_code, stdout, stderr


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

    Uses cmdkey to store a credential in Windows Credential Manager.
    Each decoy uses a unique target (username.domain) so multiple
    decoys can coexist on the same host without overwriting each other.

    Args:
        session: Active WinRM session.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        password: Honey-token password.
        dry_run: If True, simulate without modifying the endpoint.

    Raises:
        RuntimeError: If cmdkey fails to store the credential.
    """
    target = _build_target(username, domain)
    user_principal = f"{domain}\\{username}"

    if dry_run:
        logger.info(
            f"[DRY-RUN] Would inject credential: "
            f"cmdkey /add:{target} /user:{user_principal} /pass:****"
        )
        return

    logger.info(f"Injecting credential for '{user_principal}' with target '{target}'")

    status, stdout, stderr = _run_cmd(
        session,
        "cmdkey",
        (f"/add:{target}", f"/user:{user_principal}", f"/pass:{password}"),
    )

    if status != 0:
        raise RuntimeError(
            f"cmdkey /add failed (exit code {status}). "
            f"stdout: {stdout}. stderr: {stderr}"
        )

    logger.info(f"Credential injected successfully. Output: {stdout}")

    # Verify the credential was stored
    _verify_credential(session, target, user_principal)


def _verify_credential(session: winrm.Session, target: str,
                        user_principal: str) -> None:
    """Verifies that a credential was successfully stored by listing entries.

    Runs cmdkey /list and checks if the expected target appears in the output.

    Args:
        session: Active WinRM session.
        target: The cmdkey target to look for.
        user_principal: The expected user principal for logging.
    """
    status, stdout, stderr = _run_cmd(session, "cmdkey", ("/list",))

    if target.lower() in stdout.lower():
        logger.info(f"Verified: credential for '{user_principal}' found in Credential Manager")
    else:
        logger.warning(
            f"Verification: credential for '{user_principal}' with target '{target}' "
            f"was not found in cmdkey /list output. It may still have been stored "
            f"under a different user session."
        )


def remove_credential_decoy(session: winrm.Session, domain: str,
                            username: str, dry_run: bool = False) -> None:
    """Removes a specific honey-token cached credential from the endpoint.

    Uses the same unique target (username.domain) that was used during injection
    to ensure only the specific decoy credential is removed.

    Args:
        session: Active WinRM session.
        domain: Domain name (e.g., 'NTT.local').
        username: Honey-token username (e.g., 'sql-decoy').
        dry_run: If True, simulate without modifying the endpoint.
    """
    target = _build_target(username, domain)

    if dry_run:
        logger.info(f"[DRY-RUN] Would remove credential: cmdkey /delete:{target}")
        return

    logger.info(f"Removing credential with target '{target}'")

    status, stdout, stderr = _run_cmd(session, "cmdkey", (f"/delete:{target}",))

    if status != 0:
        # Non-zero exit is acceptable — the credential might already be removed (idempotent)
        logger.warning(
            f"cmdkey /delete returned exit code {status} for target '{target}'. "
            f"The credential may already have been removed. Details: {stderr}"
        )
    else:
        logger.info(f"Credential with target '{target}' removed successfully. Output: {stdout}")
