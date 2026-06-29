"""
config.py — Configuration Loading and Validation

Loads the JSON config file and validates all required fields
before the application proceeds with deploy or cleanup operations.
"""

import os
import re
import json
import logging

logger = logging.getLogger("honey_token_gen.config")

# Regex pattern for basic SPN format validation: service/host or service/host:port
SPN_PATTERN = re.compile(r"^[A-Za-z0-9_-]+/[A-Za-z0-9._-]+(:\d+)?$")


def load_config(config_path: str) -> dict:
    """Loads and validates configuration from a JSON file.

    Args:
        config_path: Path to the configuration JSON file.

    Returns:
        The parsed and validated configuration dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If configuration is invalid or missing required keys.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    logger.info(f"Loading configuration from '{config_path}'")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in configuration file: {e}")

    _validate_config(config)
    logger.info("Configuration loaded and validated successfully")
    return config


def _validate_config(config: dict) -> None:
    """Validates all configuration keys, structures, and values.

    Args:
        config: Configuration dictionary to validate.

    Raises:
        ValueError: If any validation check fails.
    """
    # --- Root-level keys ---
    required_root_keys = ["domain_controller", "decoys", "endpoints"]
    for key in required_root_keys:
        if key not in config:
            raise ValueError(f"Missing required top-level key: '{key}'")

    # --- Domain Controller section ---
    dc = config["domain_controller"]
    required_dc_keys = ["ip", "domain_name", "ldaps_port", "admin_username", "admin_password", "decoy_ou"]
    for key in required_dc_keys:
        if key not in dc:
            raise ValueError(f"Missing required domain_controller field: '{key}'")

    # --- Decoys section ---
    if not isinstance(config["decoys"], list) or len(config["decoys"]) == 0:
        raise ValueError("'decoys' must be a non-empty list of decoy definitions")

    seen_usernames = set()
    for idx, decoy in enumerate(config["decoys"]):
        for key in ["username", "password", "description"]:
            if key not in decoy:
                raise ValueError(f"Decoy at index {idx} is missing required field '{key}'")

        username = decoy["username"]

        # Check for duplicate usernames
        if username in seen_usernames:
            raise ValueError(f"Duplicate decoy username found: '{username}'")
        seen_usernames.add(username)

        # Validate SPNs (optional — missing or empty list is allowed)
        if "spns" in decoy and decoy["spns"]:
            if not isinstance(decoy["spns"], list):
                raise ValueError(f"Decoy '{username}': 'spns' field must be a list")

            for spn in decoy["spns"]:
                if not SPN_PATTERN.match(spn):
                    raise ValueError(
                        f"Decoy '{username}': Invalid SPN format '{spn}'. "
                        f"Expected format: 'service/host' or 'service/host:port'"
                    )

    # --- Endpoints section ---
    if not isinstance(config["endpoints"], list) or len(config["endpoints"]) == 0:
        raise ValueError("'endpoints' must be a non-empty list of endpoint definitions")

    for idx, endpoint in enumerate(config["endpoints"]):
        for key in ["ip", "hostname", "winrm_username", "winrm_password", "winrm_transport"]:
            if key not in endpoint:
                raise ValueError(f"Endpoint at index {idx} is missing required field '{key}'")

