import logging
import winrm

logger = logging.getLogger("honey_token_gen.winrm")

def get_winrm_session(ip, username, password, transport="ntlm"):
    """Creates a WinRM session for a given endpoint.
    
    Args:
        ip (str): IP address of the target workstation.
        username (str): Admin username for WinRM.
        password (str): Admin password.
        transport (str): WinRM transport mechanism (default 'ntlm').
        
    Returns:
        winrm.Session: A winrm Session object.
    """
    # Using HTTP on port 5985 for default lab setup.
    endpoint = f"http://{ip}:5985/wsman"
    logger.info(f"Connecting to endpoint {ip} via WinRM ({transport})")
    
    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport
    )
    return session

def execute_cmd(session, command, args=()):
    """Executes a command via cmd.exe on the remote session.
    
    Args:
        session (winrm.Session): The WinRM session.
        command (str): Command to execute.
        args (tuple): Command arguments.
        
    Returns:
        tuple: (status_code, stdout, stderr)
    """
    res = session.run_cmd(command, args)
    stdout = res.std_out.decode('utf-8', errors='ignore').strip()
    stderr = res.std_err.decode('utf-8', errors='ignore').strip()
    return res.status_code, stdout, stderr

def inject_credential_decoy(session, domain, username, password, dry_run=False):
    """Injects a cached credential decoy on the endpoint.
    
    We use cmdkey to store a persistent Windows credential targeting the domain.
    
    Args:
        session (winrm.Session): Active WinRM session.
        domain (str): Domain name (e.g. NTT.local).
        username (str): Honey-token username.
        password (str): Honey-token password.
        dry_run (bool): Dry-run flag.
    """
    target = f"*.{domain}" # Target pattern for wildcard matching domain services
    user_principal = f"{domain}\\{username}"
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would run: cmdkey /add:{target} /user:{user_principal} /pass:****")
        return

    logger.info(f"Injecting credential decoy '{user_principal}' targeting '{target}'...")
    
    # Run cmdkey command
    status, stdout, stderr = execute_cmd(session, "cmdkey", ("/add:" + target, "/user:" + user_principal, "/pass:" + password))
    
    if status != 0:
        raise RuntimeError(f"cmdkey failed with exit code {status}. Error: {stderr}")
        
    logger.info(f"Successfully injected credential on host. Output: {stdout}")

def remove_credential_decoy(session, domain, username, dry_run=False):
    """Removes a previously injected credential decoy from the endpoint.
    
    Args:
        session (winrm.Session): Active WinRM session.
        domain (str): Domain name (e.g. NTT.local).
        username (str): Honey-token username.
        dry_run (bool): Dry-run flag.
    """
    target = f"*.{domain}"
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would run: cmdkey /delete:{target}")
        return

    logger.info(f"Removing credential decoy targeting '{target}'...")
    
    # Run cmdkey delete command
    status, stdout, stderr = execute_cmd(session, "cmdkey", ("/delete:" + target,))
    
    # If the credential wasn't there, cmdkey might return non-zero. That is fine for idempotency.
    if status != 0:
        logger.warning(f"cmdkey /delete returned exit code {status}. It might already be removed. Details: {stderr}")
    else:
        logger.info(f"Credential targeting '{target}' removed successfully. Output: {stdout}")
