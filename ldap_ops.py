import logging
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, SUBTREE

logger = logging.getLogger("honey_token_gen.ldap")

def get_connection(ip, domain, admin_username, admin_password, port=636):
    """Establishes an LDAP/LDAPS connection to the Domain Controller.
    
    Args:
        ip (str): DC IP address.
        domain (str): Domain name (e.g. NTT.local).
        admin_username (str): Admin username (e.g. NTT\\administrator).
        admin_password (str): Admin password.
        port (int): LDAPS/LDAP port (636 or 389).
        
    Returns:
        Connection: ldap3 Connection object.
    """
    use_ssl = (port == 636)
    server = Server(ip, port=port, use_ssl=use_ssl, get_info=ALL)
    
    # Authenticate. Admin username might already contain domain suffix/prefix.
    logger.info(f"Connecting to DC at {ip}:{port} (SSL: {use_ssl})")
    conn = Connection(
        server, 
        user=admin_username, 
        password=admin_password, 
        auto_bind=True
    )
    logger.info("LDAP connection established successfully")
    return conn

def create_ou_if_not_exists(conn, decoy_ou, dry_run=False):
    """Creates the decoy OU in Active Directory if it does not already exist.
    
    Args:
        conn (Connection): Active LDAP connection.
        decoy_ou (str): The DN of the OU to create (e.g. OU=Decoys,DC=NTT,DC=local).
        dry_run (bool): If True, simulate changes without modifying AD.
    """
    if dry_run:
        parts = decoy_ou.split(',', 1)
        ou_name = parts[0].split('=', 1)[1]
        logger.info(f"[DRY-RUN] Would check/create OU '{ou_name}' at '{decoy_ou}'")
        return

    if conn.search(decoy_ou, '(objectClass=organizationalUnit)', search_scope=SUBTREE):
        logger.info(f"Decoy OU '{decoy_ou}' already exists.")
        return

    # Extract the OU name and parent DN
    parts = decoy_ou.split(',', 1)
    ou_name = parts[0].split('=', 1)[1]
        
    logger.info(f"Creating Decoy OU: {decoy_ou}")
    success = conn.add(decoy_ou, 'organizationalUnit', {'ou': ou_name})
    if not success:
        raise RuntimeError(f"Failed to create Decoy OU: {conn.result}")
    logger.info("Decoy OU created successfully")

def deploy_ldap_decoy(conn, decoy, decoy_ou, domain_name, dry_run=False):
    """Deploys a single decoy user account in Active Directory.
    
    Args:
        conn (Connection): Active LDAP connection.
        decoy (dict): Decoy config containing 'username', 'password', 'spns', 'description'.
        decoy_ou (str): DN of target OU.
        domain_name (str): Domain name.
        dry_run (bool): Dry-run flag.
    """
    username = decoy["username"]
    password = decoy["password"]
    spns = decoy["spns"]
    description = decoy["description"]
    
    dn = f"CN={username},{decoy_ou}"
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would create/verify user '{username}' with SPNs {spns}")
        return

    # Check if account already exists
    exists = conn.search(dn, '(objectClass=user)', search_scope=SUBTREE)
    
    if exists:
        logger.info(f"Decoy account '{username}' already exists at DN '{dn}' (Idempotent: skipping creation)")
        conn.modify(dn, {
            'description': [(MODIFY_REPLACE, [description])],
            'servicePrincipalName': [(MODIFY_REPLACE, spns)]
        })
        return

    logger.info(f"Creating user account '{username}'...")
    attributes = {
        'cn': username,
        'sAMAccountName': username,
        'userPrincipalName': f"{username}@{domain_name}",
        'givenName': username.split('-')[0].capitalize(),
        'sn': 'Decoy',
        'displayName': f"Decoy {username}",
        'description': description,
        'objectClass': ['top', 'person', 'organizationalPerson', 'user']
    }
    
    # 1. Create the user object
    if not conn.add(dn, attributes=attributes):
        raise RuntimeError(f"Failed to create user object '{username}': {conn.result}")
        
    try:
        # 2. Set the password (must be double quoted and encoded as UTF-16LE)
        unicode_password = f'"{password}"'.encode('utf-16-le')
        if not conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_password])]}) :
            raise RuntimeError(f"Failed to set password for '{username}': {conn.result}")
            
        # 3. Enable user account (UAC 512 = NORMAL_ACCOUNT)
        if not conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]}):
            raise RuntimeError(f"Failed to enable user account '{username}': {conn.result}")
            
        # 4. Assign SPNs
        if spns:
            if not conn.modify(dn, {'servicePrincipalName': [(MODIFY_REPLACE, spns)]}):
                raise RuntimeError(f"Failed to assign SPNs to '{username}': {conn.result}")
                
        logger.info(f"Decoy user '{username}' deployed successfully.")
    except Exception as e:
        logger.error(f"Error configuring account '{username}', performing cleanup roll-back: {e}")
        conn.delete(dn)
        raise

def cleanup_ldap_decoy(conn, username, decoy_ou, dry_run=False):
    """Deletes a decoy user account from AD.
    
    Args:
        conn (Connection): Active LDAP connection.
        username (str): Target decoy username.
        decoy_ou (str): DN of target OU.
        dry_run (bool): Dry-run flag.
    """
    dn = f"CN={username},{decoy_ou}"
    
    if dry_run:
        logger.info(f"[DRY-RUN] Would delete user '{username}' (DN: {dn})")
        return

    # Check if exists
    exists = conn.search(dn, '(objectClass=user)', search_scope=SUBTREE)
    if not exists:
        logger.info(f"Decoy account '{username}' does not exist (skipping).")
        return

    logger.info(f"Deleting user account '{username}'...")
    if not conn.delete(dn):
        logger.warning(f"Could not delete user account '{username}': {conn.result}")
    else:
        logger.info(f"Successfully deleted user account '{username}'")

def delete_ou_if_empty(conn, decoy_ou, dry_run=False):
    """Deletes the decoy OU if it has no children.
    
    Args:
        conn (Connection): Active LDAP connection.
        decoy_ou (str): DN of target OU.
        dry_run (bool): Dry-run flag.
    """
    if dry_run:
        logger.info(f"[DRY-RUN] Would check and delete empty OU '{decoy_ou}'")
        return

    if not conn.search(decoy_ou, '(objectClass=organizationalUnit)', search_scope=SUBTREE):
        return

    logger.info(f"Deleting empty Decoy OU: {decoy_ou}")
    if not conn.delete(decoy_ou):
        logger.warning(f"Could not delete OU '{decoy_ou}': {conn.result}")
    else:
        logger.info("Successfully deleted Decoy OU")
