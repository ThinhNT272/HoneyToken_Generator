"""
honey_token_gen.py — Honey Token Generator CLI

Main entry point for the application. Provides two commands:
- deploy: Creates honey-token accounts in AD and injects cached credentials on endpoints
- cleanup: Removes all deployed honey-tokens and cleans up the environment

Usage:
    python honey_token_gen.py deploy --config config.json [--dry-run]
    python honey_token_gen.py cleanup --config config.json [--dry-run]
    python honey_token_gen.py --help
"""

import os
import sys
import json
import random
import logging
import argparse
from datetime import datetime

from config import load_config
from ldap_ops import (
    get_connection,
    create_ou_if_not_exists,
    deploy_ldap_decoy,
    cleanup_ldap_decoy,
    delete_ou_if_empty,
)
from winrm_ops import (
    get_winrm_session,
    inject_credential_decoy,
    remove_credential_decoy,
)

# --- Constants ---
LIST_FILE = "list.json"
LOG_FILE = "honey_token_gen.log"


def setup_logging() -> None:
    """Configures logging to output to both console and a log file.

    Console shows INFO level and above.
    Log file captures DEBUG level and above for troubleshooting.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Console handler — INFO level
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    console_handler.setFormatter(console_format)

    # File handler — DEBUG level for detailed troubleshooting
    file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    file_handler.setFormatter(file_format)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


logger = logging.getLogger("honey_token_gen")


def _distribute_decoys(decoys_pool: list, endpoints: list,
                       min_per_host: int, max_per_host: int) -> dict:
    """Randomly distributes decoys across endpoints.

    Shuffles the decoy pool and assigns a random number of decoys
    (between min and max) to each endpoint. If the pool runs out,
    remaining endpoints receive fewer decoys.

    Args:
        decoys_pool: List of decoy definitions from config.
        endpoints: List of endpoint definitions from config.
        min_per_host: Minimum number of decoys per host.
        max_per_host: Maximum number of decoys per host.

    Returns:
        A dict mapping endpoint hostname to a list of decoy definitions.
        Example: {"WS01": [decoy1, decoy2], "WS02": [decoy3]}
    """
    # Shuffle decoys for random distribution
    pool = list(decoys_pool)
    random.shuffle(pool)

    distribution = {}
    pool_index = 0

    for endpoint in endpoints:
        hostname = endpoint["hostname"]
        remaining = len(pool) - pool_index

        if remaining <= 0:
            logger.warning(
                f"Decoy pool exhausted — no decoys available for host '{hostname}'"
            )
            distribution[hostname] = []
            continue

        # Pick a random count, but don't exceed remaining pool size
        count = random.randint(min_per_host, max_per_host)
        count = min(count, remaining)

        distribution[hostname] = pool[pool_index:pool_index + count]
        pool_index += count

        logger.info(f"Assigned {count} decoy(s) to host '{hostname}'")

    return distribution


def cmd_deploy(args: argparse.Namespace) -> None:
    """Orchestrates the full deployment workflow.

    1. Loads config
    2. Connects to DC via LDAP
    3. Creates decoy OU
    4. Distributes decoys randomly across endpoints
    5. For each endpoint: create AD accounts + inject cached credentials
    6. Writes list.json output file

    Args:
        args: Parsed CLI arguments (config path, dry-run flag).
    """
    config_path = args.config
    dry_run = args.dry_run

    logger.info("=" * 60)
    logger.info(f"DEPLOY started (dry-run: {dry_run})")
    logger.info("=" * 60)

    # --- Load configuration ---
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    dc_config = config["domain_controller"]
    settings = config["deployment_settings"]
    decoys_pool = config["decoys"]
    endpoints = config["endpoints"]

    # --- Check if a deployment already exists ---
    if os.path.exists(LIST_FILE) and not dry_run:
        logger.error(
            f"Deployment record '{LIST_FILE}' already exists. "
            f"Please run 'cleanup' first before deploying again."
        )
        sys.exit(1)

    # --- Connect to Active Directory ---
    ldap_conn = None
    try:
        if not dry_run:
            ldap_conn = get_connection(
                ip=dc_config["ip"],
                domain=dc_config["domain_name"],
                admin_username=dc_config["admin_username"],
                admin_password=dc_config["admin_password"],
                port=dc_config["ldaps_port"],
            )
        else:
            logger.info("[DRY-RUN] Simulating LDAP connection to DC")
    except Exception as e:
        logger.error(f"Failed to connect to Domain Controller via LDAP: {e}")
        sys.exit(1)

    # --- Create Decoy OU ---
    try:
        create_ou_if_not_exists(ldap_conn, dc_config["decoy_ou"], dry_run=dry_run)
    except Exception as e:
        logger.error(f"Failed to create Decoy OU: {e}")
        sys.exit(1)

    # --- Distribute decoys across endpoints ---
    distribution = _distribute_decoys(
        decoys_pool=decoys_pool,
        endpoints=endpoints,
        min_per_host=settings["min_decoys_per_host"],
        max_per_host=settings["max_decoys_per_host"],
    )

    # --- Deploy to each endpoint ---
    deployed_decoys = []
    stats = {"ad_success": 0, "ad_fail": 0, "cred_success": 0, "cred_fail": 0}

    for endpoint in endpoints:
        hostname = endpoint["hostname"]
        ip = endpoint["ip"]
        assigned_decoys = distribution.get(hostname, [])

        if not assigned_decoys:
            continue

        logger.info(f"--- Processing host '{hostname}' ({ip}) ---")

        # Connect to endpoint via WinRM
        winrm_sess = None
        try:
            if not dry_run:
                winrm_sess = get_winrm_session(
                    ip=ip,
                    username=endpoint["winrm_username"],
                    password=endpoint["winrm_password"],
                    transport=endpoint["winrm_transport"],
                )
            else:
                logger.info(f"[DRY-RUN] Simulating WinRM connection to '{hostname}'")
        except Exception as e:
            logger.error(
                f"Failed to connect to '{hostname}' via WinRM: {e}. "
                f"Skipping all decoys for this host."
            )
            stats["cred_fail"] += len(assigned_decoys)
            continue

        # Deploy each assigned decoy
        for decoy in assigned_decoys:
            username = decoy["username"]

            # Step 1: Create AD account via LDAP
            try:
                deploy_ldap_decoy(
                    conn=ldap_conn,
                    decoy=decoy,
                    decoy_ou=dc_config["decoy_ou"],
                    domain_name=dc_config["domain_name"],
                    dry_run=dry_run,
                )
                stats["ad_success"] += 1
            except Exception as e:
                logger.error(
                    f"Failed to deploy '{username}' to AD: {e}. "
                    f"Skipping credential injection for this decoy."
                )
                stats["ad_fail"] += 1
                continue

            # Step 2: Inject cached credential on endpoint via WinRM
            try:
                inject_credential_decoy(
                    session=winrm_sess,
                    domain=dc_config["domain_name"],
                    username=username,
                    password=decoy["password"],
                    dry_run=dry_run,
                )
                stats["cred_success"] += 1

                # Record successful deployment
                deployed_decoys.append({
                    "username": username,
                    "spns": decoy["spns"],
                    "description": decoy["description"],
                    "workstation": hostname,
                })
            except Exception as e:
                logger.error(
                    f"Failed to inject credential for '{username}' on '{hostname}': {e}"
                )
                stats["cred_fail"] += 1

    # --- Write deployment record ---
    if not dry_run:
        now = datetime.now()
        output_data = {
            "deployment_id": now.strftime("%Y%m%d_%H%M%S"),
            "domain": dc_config["domain_name"],
            "deployed_at": now.isoformat(),
            "decoys": deployed_decoys,
        }

        try:
            with open(LIST_FILE, "w") as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Deployment record written to '{LIST_FILE}'")
        except Exception as e:
            logger.error(f"Failed to write deployment record: {e}")
    else:
        logger.info(
            f"[DRY-RUN] Would write deployment record to '{LIST_FILE}' "
            f"containing {len(deployed_decoys)} decoy(s)"
        )

    # --- Print summary ---
    logger.info("=" * 60)
    logger.info("DEPLOY SUMMARY")
    logger.info(f"  AD accounts created:         {stats['ad_success']}")
    logger.info(f"  AD accounts failed:          {stats['ad_fail']}")
    logger.info(f"  Credentials injected:        {stats['cred_success']}")
    logger.info(f"  Credentials failed:          {stats['cred_fail']}")
    logger.info(f"  Total decoys deployed:       {len(deployed_decoys)}")
    logger.info("=" * 60)


def cmd_cleanup(args: argparse.Namespace) -> None:
    """Orchestrates the full cleanup workflow.

    1. Reads list.json to determine what was deployed
    2. Loads config for connection credentials
    3. For each deployed decoy: removes cached credential + deletes AD account
    4. Deletes the Decoy OU if empty
    5. Deletes list.json

    Args:
        args: Parsed CLI arguments (config path, dry-run flag).
    """
    config_path = args.config
    dry_run = args.dry_run

    logger.info("=" * 60)
    logger.info(f"CLEANUP started (dry-run: {dry_run})")
    logger.info("=" * 60)

    # --- Load deployment record ---
    if not os.path.exists(LIST_FILE):
        logger.warning(
            f"Deployment record '{LIST_FILE}' not found. "
            f"No deployed decoys to clean up."
        )
        sys.exit(1)

    try:
        with open(LIST_FILE, "r") as f:
            list_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse deployment record '{LIST_FILE}': {e}")
        sys.exit(1)

    deployed_decoys = list_data.get("decoys", [])
    if not deployed_decoys:
        logger.info("No decoys found in deployment record. Nothing to clean up.")
        sys.exit(0)

    logger.info(f"Found {len(deployed_decoys)} deployed decoy(s) to clean up")

    # --- Load configuration ---
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    dc_config = config["domain_controller"]
    endpoints_map = {ep["hostname"]: ep for ep in config["endpoints"]}

    # --- Connect to Active Directory ---
    ldap_conn = None
    try:
        if not dry_run:
            ldap_conn = get_connection(
                ip=dc_config["ip"],
                domain=dc_config["domain_name"],
                admin_username=dc_config["admin_username"],
                admin_password=dc_config["admin_password"],
                port=dc_config["ldaps_port"],
            )
        else:
            logger.info("[DRY-RUN] Simulating LDAP connection to DC")
    except Exception as e:
        logger.error(f"Failed to connect to Domain Controller via LDAP: {e}")
        sys.exit(1)

    # --- Clean up each deployed decoy ---
    # Cache WinRM sessions to avoid reconnecting for every decoy on the same host
    winrm_sessions = {}
    stats = {"cred_success": 0, "cred_fail": 0, "ad_success": 0, "ad_fail": 0}

    for decoy in deployed_decoys:
        username = decoy["username"]
        hostname = decoy["workstation"]

        logger.info(f"--- Cleaning up decoy '{username}' from '{hostname}' ---")

        # Step 1: Remove cached credential from endpoint via WinRM
        if hostname in endpoints_map:
            endpoint = endpoints_map[hostname]

            # Connect if not already connected
            if hostname not in winrm_sessions:
                try:
                    if not dry_run:
                        winrm_sessions[hostname] = get_winrm_session(
                            ip=endpoint["ip"],
                            username=endpoint["winrm_username"],
                            password=endpoint["winrm_password"],
                            transport=endpoint["winrm_transport"],
                        )
                    else:
                        winrm_sessions[hostname] = None
                        logger.info(
                            f"[DRY-RUN] Simulating WinRM connection to '{hostname}'"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to connect to '{hostname}' via WinRM: {e}"
                    )
                    winrm_sessions[hostname] = None

            session = winrm_sessions[hostname]
            if session or dry_run:
                try:
                    remove_credential_decoy(
                        session=session,
                        domain=dc_config["domain_name"],
                        username=username,
                        dry_run=dry_run,
                    )
                    stats["cred_success"] += 1
                except Exception as e:
                    logger.error(
                        f"Failed to remove credential for '{username}' "
                        f"on '{hostname}': {e}"
                    )
                    stats["cred_fail"] += 1
            else:
                logger.warning(
                    f"No WinRM session available for '{hostname}' — "
                    f"skipping credential removal for '{username}'"
                )
                stats["cred_fail"] += 1
        else:
            logger.warning(
                f"Endpoint '{hostname}' not found in config — "
                f"skipping credential removal for '{username}'"
            )
            stats["cred_fail"] += 1

        # Step 2: Delete AD account via LDAP
        try:
            cleanup_ldap_decoy(
                conn=ldap_conn,
                username=username,
                decoy_ou=dc_config["decoy_ou"],
                dry_run=dry_run,
            )
            stats["ad_success"] += 1
        except Exception as e:
            logger.error(f"Failed to delete AD account '{username}': {e}")
            stats["ad_fail"] += 1

    # --- Delete the Decoy OU if empty ---
    try:
        delete_ou_if_empty(ldap_conn, dc_config["decoy_ou"], dry_run=dry_run)
    except Exception as e:
        logger.error(f"Failed to clean up Decoy OU: {e}")

    # --- Delete the deployment record file ---
    if not dry_run:
        try:
            os.remove(LIST_FILE)
            logger.info(f"Deleted deployment record '{LIST_FILE}'")
        except Exception as e:
            logger.error(f"Failed to delete '{LIST_FILE}': {e}")
    else:
        logger.info(f"[DRY-RUN] Would delete deployment record '{LIST_FILE}'")

    # --- Print summary ---
    logger.info("=" * 60)
    logger.info("CLEANUP SUMMARY")
    logger.info(f"  Credentials removed:         {stats['cred_success']}")
    logger.info(f"  Credentials failed:          {stats['cred_fail']}")
    logger.info(f"  AD accounts deleted:         {stats['ad_success']}")
    logger.info(f"  AD accounts failed:          {stats['ad_fail']}")
    logger.info("=" * 60)


def main():
    """CLI entry point — parses arguments and dispatches to deploy or cleanup."""
    parser = argparse.ArgumentParser(
        prog="honey_token_gen",
        description=(
            "Honey Token Generator — Deploy and clean up deception "
            "honey-token credentials in Active Directory environments."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- Deploy subcommand ---
    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Deploy decoy accounts to AD and inject cached credentials on endpoints",
    )
    deploy_parser.add_argument(
        "--config",
        default="config.json",
        help="Path to the JSON configuration file (default: config.json)",
    )
    deploy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate deployment without making any changes to AD or endpoints",
    )

    # --- Cleanup subcommand ---
    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Remove all deployed decoy accounts and cached credentials",
    )
    cleanup_parser.add_argument(
        "--config",
        default="config.json",
        help="Path to the JSON configuration file (default: config.json)",
    )
    cleanup_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate cleanup without making any changes to AD or endpoints",
    )

    args = parser.parse_args()

    # Show help if no command is provided
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Initialize logging after argument parsing
    setup_logging()

    # Dispatch to the appropriate command handler
    if args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)


if __name__ == "__main__":
    main()
