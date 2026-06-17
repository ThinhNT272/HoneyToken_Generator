"""
ldap_ops.py — Active Directory LDAP Operations

Handles all interactions with the Domain Controller via LDAP/LDAPS:
- Establishing connections
- Creating and deleting the Decoy Organizational Unit (OU)
- Creating and deleting honey-token user/service accounts with SPNs
"""

import ssl
import logging
from ldap3 import (
    Server,
    Connection,
    Tls,
    NONE,
    BASE,
    LEVEL,
    SUBTREE,
    MODIFY_REPLACE,
)
from ldap3.core.exceptions import (
    LDAPNoSuchObjectResult,
    LDAPEntryAlreadyExistsResult,
    LDAPException,
)

logger = logging.getLogger("honey_token_gen.ldap")


def get_connection(ip: str, domain: str, admin_username: str,
                   admin_password: str, port: int = 636) -> Connection:
    """Establishes an LDAP/LDAPS connection to the Domain Controller.

    - Port 636: Uses LDAPS (SSL from the start).
    - Port 389: Uses plain LDAP then upgrades to StartTLS for encryption.

    StartTLS is required on port 389 because Active Directory refuses to
    modify the unicodePwd attribute (set passwords) over unencrypted connections.
    Certificate validation is disabled for lab environments with self-signed certs.

    Args:
        ip: DC IP address (e.g., '192.168.100.50').
        domain: Domain name (e.g., 'NTT.local').
        admin_username: Admin username (e.g., 'NTT\\administrator').
        admin_password: Admin password.
        port: LDAPS (636) or LDAP (389) port.

    Returns:
        An authenticated ldap3 Connection object.

    Raises:
        LDAPException: If the connection or authentication fails.
    """
    # TLS config — disable certificate validation for lab self-signed certs
    tls_config = Tls(validate=ssl.CERT_NONE)

    use_ssl = (port == 636)

    if use_ssl:
        # LDAPS: SSL from the start on port 636
        server = Server(ip, port=port, use_ssl=True, tls=tls_config, get_info=NONE)
        logger.info(f"Connecting to Domain Controller at {ip}:{port} (LDAPS)")

        conn = Connection(
            server,
            user=admin_username,
            password=admin_password,
            auto_bind=True,
            raise_exceptions=True,
        )
    else:
        # LDAP + StartTLS: connect on port 389, then upgrade to encrypted
        server = Server(ip, port=port, use_ssl=False, tls=tls_config, get_info=NONE)
        logger.info(f"Connecting to Domain Controller at {ip}:{port} (LDAP + StartTLS)")

        conn = Connection(
            server,
            user=admin_username,
            password=admin_password,
            auto_bind=False,
            raise_exceptions=True,
        )
        conn.open()
        conn.start_tls()
        conn.bind()
        logger.info("StartTLS negotiated successfully")

    logger.info("LDAP connection established successfully")
    return conn


def create_ou_if_not_exists(conn: Connection, decoy_ou: str,
                            dry_run: bool = False) -> None:
    """Creates the Decoy OU in Active Directory if it does not already exist.

    Searches from the parent DN for the specific OU to avoid false positives
    from SUBTREE search issues.

    Args:
        conn: Active LDAP connection.
        decoy_ou: The full DN of the OU (e.g., 'OU=Decoys,DC=NTT,DC=local').
        dry_run: If True, simulate without modifying AD.
    """
    # Parse the OU name and parent DN from the full DN
    # e.g., "OU=Decoys,DC=NTT,DC=local" -> ou_name="Decoys", parent_dn="DC=NTT,DC=local"
    parts = decoy_ou.split(",", 1)
    ou_name = parts[0].split("=", 1)[1]
    parent_dn = parts[1] if len(parts) > 1 else ""

    if dry_run:
        logger.info(f"[DRY-RUN] Would check/create OU '{ou_name}' at '{decoy_ou}'")
        return

    # Search from the parent DN for the specific OU
    try:
        found = conn.search(
            search_base=parent_dn,
            search_filter=f"(&(objectClass=organizationalUnit)(ou={ou_name}))",
            search_scope=LEVEL,
        )
        if found and conn.entries:
            logger.info(f"Decoy OU '{decoy_ou}' already exists (skipping creation)")
            return
    except LDAPNoSuchObjectResult:
        # Parent DN doesn't exist — this is a bigger problem
        raise RuntimeError(
            f"Parent DN '{parent_dn}' does not exist. "
            f"Cannot create OU '{decoy_ou}'"
        )

    # Create the OU
    logger.info(f"Creating Decoy OU: '{decoy_ou}'")
    try:
        conn.add(decoy_ou, "organizationalUnit", {"ou": ou_name})
        logger.info("Decoy OU created successfully")
    except LDAPEntryAlreadyExistsResult:
        logger.info(f"Decoy OU '{decoy_ou}' already exists (race condition, safe to continue)")


def _account_exists(conn: Connection, dn: str) -> bool:
    """Checks if an AD object exists at the given DN.

    Uses BASE scope search on the exact DN, which is the correct way
    to check for existence of a specific object.

    Args:
        conn: Active LDAP connection.
        dn: The full DN to check.

    Returns:
        True if the object exists, False otherwise.
    """
    try:
        found = conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
        )
        return found and len(conn.entries) > 0
    except LDAPNoSuchObjectResult:
        return False


def deploy_ldap_decoy(conn: Connection, decoy: dict, decoy_ou: str,
                      domain_name: str, dry_run: bool = False) -> None:
    """Deploys a single honey-token user account in Active Directory.

    Creates a user account in the Decoy OU with the specified username,
    password, description, and Service Principal Names (SPNs). If the account
    already exists, it updates the description and SPNs (idempotent).

    Args:
        conn: Active LDAP connection.
        decoy: Decoy definition dict with keys: username, password, spns, description.
        decoy_ou: DN of the target OU (e.g., 'OU=Decoys,DC=NTT,DC=local').
        domain_name: Domain name (e.g., 'NTT.local').
        dry_run: If True, simulate without modifying AD.

    Raises:
        RuntimeError: If account creation or configuration fails.
    """
    username = decoy["username"]
    password = decoy["password"]
    spns = decoy["spns"]
    description = decoy["description"]

    dn = f"CN={username},{decoy_ou}"

    if dry_run:
        logger.info(f"[DRY-RUN] Would create/verify user '{username}' with SPNs {spns}")
        return

    # Check if the account already exists (idempotent)
    if _account_exists(conn, dn):
        logger.info(
            f"Decoy account '{username}' already exists at '{dn}' — "
            f"updating description and SPNs (idempotent)"
        )
        conn.modify(dn, {
            "description": [(MODIFY_REPLACE, [description])],
            "servicePrincipalName": [(MODIFY_REPLACE, spns)],
        })
        return

    # Create the user account
    logger.info(f"Creating decoy account '{username}' in '{decoy_ou}'")
    attributes = {
        "cn": username,
        "sAMAccountName": username,
        "userPrincipalName": f"{username}@{domain_name}",
        "givenName": username.split("-")[0].capitalize(),
        "sn": "Service",
        "displayName": username,
        "description": description,
        "objectClass": ["top", "person", "organizationalPerson", "user"],
    }

    conn.add(dn, attributes=attributes)
    logger.info(f"User object '{username}' created")

    # Configure the account (password, enable, SPNs)
    # If any step fails, roll back by deleting the partially-created account
    try:
        # Set password — must be double-quoted and encoded as UTF-16LE
        unicode_password = f'"{password}"'.encode("utf-16-le")
        conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [unicode_password])]})
        logger.info(f"Password set for '{username}'")

        # Enable the account — UAC 512 = NORMAL_ACCOUNT
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        logger.info(f"Account '{username}' enabled")

        # Assign SPNs for Kerberoasting detection
        if spns:
            conn.modify(dn, {"servicePrincipalName": [(MODIFY_REPLACE, spns)]})
            logger.info(f"SPNs {spns} assigned to '{username}'")

        logger.info(f"Decoy account '{username}' deployed successfully")

    except LDAPException as e:
        # Roll back: delete the partially created account
        logger.error(
            f"Failed to configure account '{username}': {e}. "
            f"Rolling back — deleting partial account."
        )
        try:
            conn.delete(dn)
        except LDAPException:
            logger.error(f"Rollback failed: could not delete '{dn}'")
        raise RuntimeError(f"Failed to deploy decoy '{username}': {e}")


def cleanup_ldap_decoy(conn: Connection, username: str, decoy_ou: str,
                       dry_run: bool = False) -> None:
    """Deletes a honey-token user account from Active Directory.

    Skips silently if the account does not exist (idempotent).

    Args:
        conn: Active LDAP connection.
        username: The decoy account's sAMAccountName.
        decoy_ou: DN of the target OU.
        dry_run: If True, simulate without modifying AD.
    """
    dn = f"CN={username},{decoy_ou}"

    if dry_run:
        logger.info(f"[DRY-RUN] Would delete user '{username}' (DN: {dn})")
        return

    # Check if the account exists before attempting deletion
    if not _account_exists(conn, dn):
        logger.info(f"Decoy account '{username}' does not exist (skipping)")
        return

    logger.info(f"Deleting decoy account '{username}' from AD")
    try:
        conn.delete(dn)
        logger.info(f"Successfully deleted account '{username}'")
    except LDAPException as e:
        logger.error(f"Failed to delete account '{username}': {e}")
        raise


def delete_ou_if_empty(conn: Connection, decoy_ou: str,
                       dry_run: bool = False) -> None:
    """Deletes the Decoy OU only if it contains no child objects.

    Searches for any children before attempting deletion to avoid
    accidentally trying to delete a non-empty OU.

    Args:
        conn: Active LDAP connection.
        decoy_ou: DN of the target OU.
        dry_run: If True, simulate without modifying AD.
    """
    if dry_run:
        logger.info(f"[DRY-RUN] Would check and delete empty OU '{decoy_ou}'")
        return

    # First, verify the OU exists
    if not _account_exists(conn, decoy_ou):
        logger.info(f"Decoy OU '{decoy_ou}' does not exist (nothing to delete)")
        return

    # Check for child objects inside the OU
    try:
        conn.search(
            search_base=decoy_ou,
            search_filter="(objectClass=*)",
            search_scope=LEVEL,
        )
        if conn.entries:
            logger.warning(
                f"Decoy OU '{decoy_ou}' still contains {len(conn.entries)} "
                f"child object(s) — skipping OU deletion"
            )
            return
    except LDAPNoSuchObjectResult:
        return

    # OU is empty, safe to delete
    logger.info(f"Deleting empty Decoy OU: '{decoy_ou}'")
    try:
        conn.delete(decoy_ou)
        logger.info("Decoy OU deleted successfully")
    except LDAPException as e:
        logger.warning(f"Could not delete OU '{decoy_ou}': {e}")
