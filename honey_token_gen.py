import os
import sys
import json
import random
import logging
import argparse
from datetime import datetime

from config import load_config
from ldap_ops import get_connection, create_ou_if_not_exists, deploy_ldap_decoy, cleanup_ldap_decoy, delete_ou_if_empty
from winrm_ops import get_winrm_session, inject_credential_decoy, remove_credential_decoy

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("honey_token_gen")

LIST_FILE = "list.json"

def cmd_deploy(args):
    """Orchestrates the deployment of honey tokens to AD and workstations."""
    config_path = args.config
    dry_run = args.dry_run
    
    logger.info(f"Starting deployment process (Dry-run: {dry_run})...")
    
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
        
    dc_config = config["domain_controller"]
    settings = config["deployment_settings"]
    decoys_pool = list(config["decoys"])
    endpoints = config["endpoints"]
    
    # Shuffle decoys to ensure randomized distribution
    random.shuffle(decoys_pool)
    
    # Connect to Active Directory
    try:
        if not dry_run:
            ldap_conn = get_connection(
                ip=dc_config["ip"],
                domain=dc_config["domain_name"],
                admin_username=dc_config["admin_username"],
                admin_password=dc_config["admin_password"],
                port=dc_config["ldaps_port"]
            )
        else:
            ldap_conn = None
            logger.info("[DRY-RUN] Simulating AD connection.")
    except Exception as e:
        logger.error(f"Failed to connect to Domain Controller via LDAP: {e}")
        sys.exit(1)
        
    # Ensure Decoy OU exists
    try:
        create_ou_if_not_exists(ldap_conn, dc_config["decoy_ou"], dry_run=dry_run)
    except Exception as e:
        logger.error(f"Failed to ensure Decoy OU exists: {e}")
        sys.exit(1)
        
    deployed_decoys = []
    decoy_index = 0
    
    for endpoint in endpoints:
        ip = endpoint["ip"]
        hostname = endpoint["hostname"]
        
        # Determine number of decoys for this host
        min_decoy = settings["min_decoys_per_host"]
        max_decoy = settings["max_decoys_per_host"]
        num_decoys = random.randint(min_decoy, max_decoy)
        
        logger.info(f"Selecting {num_decoys} decoys for host '{hostname}' ({ip})")
        
        # Connect to endpoint WinRM
        try:
            if not dry_run:
                winrm_sess = get_winrm_session(
                    ip=ip,
                    username=endpoint["winrm_username"],
                    password=endpoint["winrm_password"],
                    transport=endpoint["winrm_transport"]
                )
            else:
                winrm_sess = None
                logger.info(f"[DRY-RUN] Simulating WinRM connection to {hostname}")
        except Exception as e:
            logger.error(f"Failed to connect to endpoint '{hostname}' via WinRM: {e}. Skipping host.")
            continue
            
        for _ in range(num_decoys):
            if decoy_index >= len(decoys_pool):
                logger.warning("Ran out of unique decoys in the pool. Wrapping around/re-using decoys.")
                # Shuffle again for the next cycle
                random.shuffle(decoys_pool)
                decoy_index = 0
                
            decoy = decoys_pool[decoy_index]
            decoy_index += 1
            
            # 1. Deploy to Active Directory
            try:
                deploy_ldap_decoy(
                    conn=ldap_conn,
                    decoy=decoy,
                    decoy_ou=dc_config["decoy_ou"],
                    domain_name=dc_config["domain_name"],
                    dry_run=dry_run
                )
            except Exception as e:
                logger.error(f"Failed to deploy decoy '{decoy['username']}' to Active Directory: {e}. Skipping credential injection.")
                continue
                
            # 2. Inject cached credential on workstation endpoint
            try:
                inject_credential_decoy(
                    session=winrm_sess,
                    domain=dc_config["domain_name"],
                    username=decoy["username"],
                    password=decoy["password"],
                    dry_run=dry_run
                )
                
                # Append to list of deployed decoys
                deployed_decoys.append({
                    "username": decoy["username"],
                    "spns": decoy["spns"],
                    "description": decoy["description"],
                    "workstation": hostname
                })
            except Exception as e:
                logger.error(f"Failed to inject credential decoy on workstation '{hostname}': {e}")
                # We do not rollback AD account here as it might be successfully configured and could be needed for other endpoints.
                
    # Save the output file if not dry run
    if not dry_run:
        now = datetime.now()
        output_data = {
            "deployment_id": now.strftime("%Y%m%d_%H%M%S"),
            "domain": dc_config["domain_name"],
            "deployed_at": now.isoformat(),
            "decoys": deployed_decoys
        }
        
        try:
            with open(LIST_FILE, "w") as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Deployment record written successfully to '{LIST_FILE}'")
        except Exception as e:
            logger.error(f"Failed to write deployment record '{LIST_FILE}': {e}")
    else:
        logger.info(f"[DRY-RUN] Would write deployment record to '{LIST_FILE}' containing {len(deployed_decoys)} decoys.")
        
    logger.info("Deployment execution finished.")

def cmd_cleanup(args):
    """Cleans up the environment by removing decoy accounts, SPNs, endpoint credentials, and the list file."""
    config_path = args.config
    dry_run = args.dry_run
    
    logger.info(f"Starting cleanup process (Dry-run: {dry_run})...")
    
    if not os.path.exists(LIST_FILE):
        logger.warning(f"Deployment record file '{LIST_FILE}' not found. Cannot proceed with automatic cleanup.")
        sys.exit(1)
        
    try:
        with open(LIST_FILE, 'r') as f:
            list_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to parse deployment record '{LIST_FILE}': {e}")
        sys.exit(1)
        
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
        
    dc_config = config["domain_controller"]
    endpoints_map = {ep["hostname"]: ep for ep in config["endpoints"]}
    
    # Connect to Active Directory
    try:
        if not dry_run:
            ldap_conn = get_connection(
                ip=dc_config["ip"],
                domain=dc_config["domain_name"],
                admin_username=dc_config["admin_username"],
                admin_password=dc_config["admin_password"],
                port=dc_config["ldaps_port"]
            )
        else:
            ldap_conn = None
            logger.info("[DRY-RUN] Simulating AD connection.")
    except Exception as e:
        logger.error(f"Failed to connect to Domain Controller via LDAP: {e}")
        sys.exit(1)
        
    # Track endpoints we have already connected to for cleanup
    endpoint_sessions = {}
    
    for decoy in list_data.get("decoys", []):
        username = decoy["username"]
        hostname = decoy["workstation"]
        
        # 1. Connect and cleanup workstation endpoint
        if hostname in endpoints_map:
            endpoint = endpoints_map[hostname]
            if hostname not in endpoint_sessions:
                try:
                    if not dry_run:
                        endpoint_sessions[hostname] = get_winrm_session(
                            ip=endpoint["ip"],
                            username=endpoint["winrm_username"],
                            password=endpoint["winrm_password"],
                            transport=endpoint["winrm_transport"]
                        )
                    else:
                        endpoint_sessions[hostname] = None
                        logger.info(f"[DRY-RUN] Simulating WinRM connection for cleanup on {hostname}")
                except Exception as e:
                    logger.error(f"Failed to connect to host '{hostname}' via WinRM for cleanup: {e}")
                    endpoint_sessions[hostname] = None
            
            sess = endpoint_sessions[hostname]
            if sess or dry_run:
                try:
                    remove_credential_decoy(
                        session=sess,
                        domain=dc_config["domain_name"],
                        username=username,
                        dry_run=dry_run
                    )
                except Exception as e:
                    logger.error(f"Failed to remove credential decoy on workstation '{hostname}': {e}")
        else:
            logger.warning(f"Workstation '{hostname}' not defined in config, skipping WinRM credential cleanup.")
            
        # 2. Delete AD account
        try:
            cleanup_ldap_decoy(
                conn=ldap_conn,
                username=username,
                decoy_ou=dc_config["decoy_ou"],
                dry_run=dry_run
            )
        except Exception as e:
            logger.error(f"Failed to delete decoy account '{username}' from AD: {e}")
            
    # Clean up empty Decoy OU
    try:
        delete_ou_if_empty(ldap_conn, dc_config["decoy_ou"], dry_run=dry_run)
    except Exception as e:
        logger.error(f"Failed to clean up Decoy OU: {e}")
        
    # Delete deployment file
    if not dry_run:
        try:
            os.remove(LIST_FILE)
            logger.info(f"Deleted deployment record file '{LIST_FILE}'")
        except Exception as e:
            logger.error(f"Failed to delete deployment record file '{LIST_FILE}': {e}")
    else:
        logger.info(f"[DRY-RUN] Would delete deployment record file '{LIST_FILE}'")
        
    logger.info("Cleanup execution finished.")

def main():
    parser = argparse.ArgumentParser(
        description="Honey Token Generator CLI - Deploy and Cleanup deception credentials in AD environments."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Deploy Subparser
    deploy_parser = subparsers.add_parser("deploy", help="Deploy decoy accounts to AD and endpoints")
    deploy_parser.add_argument(
        "--config", 
        default="config.json", 
        help="Path to the JSON configuration file (default: config.json)"
    )
    deploy_parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Run without modifying AD or endpoints"
    )
    
    # Cleanup Subparser
    cleanup_parser = subparsers.add_parser("cleanup", help="Remove all deployed decoy accounts and credentials")
    cleanup_parser.add_argument(
        "--config", 
        default="config.json", 
        help="Path to the JSON configuration file (default: config.json)"
    )
    cleanup_parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Run without modifying AD or endpoints"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
        
    if args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)

if __name__ == "__main__":
    main()
