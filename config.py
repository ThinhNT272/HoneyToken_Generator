import os
import json
import logging

logger = logging.getLogger("honey_token_gen.config")

def load_config(config_path):
    """Loads and validates configuration from a JSON file.
    
    Args:
        config_path (str): Path to the configuration JSON file.
        
    Returns:
        dict: The parsed and validated configuration dictionary.
        
    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If configuration is invalid or missing required keys.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")
        
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in configuration file: {e}")
        
    validate_config(config)
    return config

def validate_config(config):
    """Validates configuration keys and structures.
    
    Args:
        config (dict): Configuration dictionary to validate.
        
    Raises:
        ValueError: If validation fails.
    """
    required_root_keys = ["domain_controller", "deployment_settings", "decoys", "endpoints"]
    for key in required_root_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration key: '{key}'")
            
    dc = config["domain_controller"]
    required_dc_keys = ["ip", "domain_name", "ldaps_port", "admin_username", "admin_password", "decoy_ou"]
    for key in required_dc_keys:
        if key not in dc:
            raise ValueError(f"Missing required domain_controller setting: '{key}'")
            
    settings = config["deployment_settings"]
    if "min_decoys_per_host" not in settings or "max_decoys_per_host" not in settings:
        raise ValueError("deployment_settings must contain 'min_decoys_per_host' and 'max_decoys_per_host'")
        
    if settings["min_decoys_per_host"] > settings["max_decoys_per_host"]:
        raise ValueError("min_decoys_per_host cannot be greater than max_decoys_per_host")
        
    if not isinstance(config["decoys"], list) or len(config["decoys"]) == 0:
        raise ValueError("config['decoys'] must be a non-empty list of decoy definitions")
        
    for idx, decoy in enumerate(config["decoys"]):
        for key in ["username", "password", "spns", "description"]:
            if key not in decoy:
                raise ValueError(f"Decoy at index {idx} is missing required field '{key}'")
        if not isinstance(decoy["spns"], list):
            raise ValueError(f"Decoy '{decoy['username']}' SPNs field must be a list")
            
    for idx, endpoint in enumerate(config["endpoints"]):
        for key in ["ip", "hostname", "winrm_username", "winrm_password", "winrm_transport"]:
            if key not in endpoint:
                raise ValueError(f"Endpoint at index {idx} is missing required field '{key}'")
