#!/usr/bin/env python3

# Synchronize network client information from a UniFi Network Controller to a phpIPAM instance.

# This script can operate in two modes:
# 1. Sync Mode (default): Updates phpIPAM based on MAC addresses. If a device is found,
#     it's updated. If not, it's created.
# 2. Nuke and Pave Mode (--nuke-and-pave): Deletes all addresses in all configured
#     subnets in phpIPAM and then creates fresh records for every client found in UniFi.

import argparse
import ipaddress
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import requests
import urllib3
import yaml

DEFAULT_CONFIG_PATH = Path("/etc/unifi2ipam/config.yaml")


@dataclass
class Config:
    unifi_url: str
    unifi_key: str
    ipam_url: str
    ipam_key: str
    verify_ssl: bool
    include_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    exclude_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)


def setup_logging(args) -> None:
    """Configure logging level and handlers based on CLI flags."""
    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )


def parse_subnets(raw: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a list of CIDR strings into network objects, exiting on any invalid entry."""
    result = []
    for cidr in raw:
        try:
            result.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as e:
            logging.error(f"Invalid subnet '{cidr}': {e}")
            raise SystemExit(1)
    return result


def is_in_filter(cfg: Config, ip: str) -> bool:
    """
    Return True if the given IP should be processed based on the configured subnet filter.

    - If include_subnets is set: only process IPs that fall within one of those subnets.
    - If exclude_subnets is set: skip IPs that fall within any of those subnets.
    - If neither is set: always process.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # malformed IP — pass through and let it fail naturally

    if cfg.include_subnets:
        return any(addr in subnet for subnet in cfg.include_subnets)
    if cfg.exclude_subnets:
        return not any(addr in subnet for subnet in cfg.exclude_subnets)
    return True


def load_config(args) -> Config:
    """
    Build a Config object by merging values from (lowest to highest precedence):
      1. YAML config file
      2. Environment variables
      3. CLI flags

    Returns:
        Config: Populated configuration object.

    Raises:
        SystemExit: If any required value is missing after merging all sources.
    """
    values = {
        "unifi_url": None,
        "unifi_key": None,
        "ipam_base_url": None,
        "ipam_app_id": None,
        "ipam_key": None,
        "insecure": False,
        "include_subnets": [],
        "exclude_subnets": [],
    }

    # 1. Config file
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    if config_path.exists():
        logging.debug(f"Loading config file: {config_path}")
        with open(config_path) as f:
            file_cfg = yaml.safe_load(f) or {}

        unifi_cfg = file_cfg.get("unifi", {})
        ipam_cfg = file_cfg.get("ipam", {})

        values["unifi_url"] = unifi_cfg.get("url")
        values["unifi_key"] = unifi_cfg.get("api_key")
        values["ipam_base_url"] = ipam_cfg.get("base_url")
        values["ipam_app_id"] = ipam_cfg.get("app_id")
        values["ipam_key"] = ipam_cfg.get("api_key")
        values["insecure"] = file_cfg.get("insecure", False)
        values["include_subnets"] = file_cfg.get("subnets", {}).get("include", [])
        values["exclude_subnets"] = file_cfg.get("subnets", {}).get("exclude", [])
    elif args.config:
        # Only error if a path was explicitly provided but doesn't exist.
        logging.error(f"Config file not found: {config_path}")
        raise SystemExit(1)

    # 2. Environment variables
    env_map = {
        "UNIFI_URL": "unifi_url",
        "UNIFI_API_KEY": "unifi_key",
        "IPAM_BASE_URL": "ipam_base_url",
        "IPAM_APP_ID": "ipam_app_id",
        "IPAM_API_KEY": "ipam_key",
    }
    for env_var, key in env_map.items():
        val = os.environ.get(env_var)
        if val:
            values[key] = val

    # 3. CLI flags
    if args.unifi_url:
        values["unifi_url"] = args.unifi_url
    if args.ipam_base_url:
        values["ipam_base_url"] = args.ipam_base_url
    if args.ipam_app_id:
        values["ipam_app_id"] = args.ipam_app_id
    if args.insecure:
        values["insecure"] = True
    if args.include_subnet:
        values["include_subnets"] = args.include_subnet
    if args.exclude_subnet:
        values["exclude_subnets"] = args.exclude_subnet

    # Derive the full IPAM URL from base URL + app ID.
    ipam_url = None
    if values["ipam_base_url"] and values["ipam_app_id"]:
        base = values["ipam_base_url"].rstrip("/")
        ipam_url = f"{base}/api/{values['ipam_app_id']}/"

    # Subnet mutual-exclusivity check — catch this before anything else.
    if values["include_subnets"] and values["exclude_subnets"]:
        logging.error("--include-subnet and --exclude-subnet (subnets.include / subnets.exclude) are mutually exclusive.")
        raise SystemExit(1)

    # Pre-flight validation — all four required fields must be present.
    missing = []
    if not values["unifi_url"]:
        missing.append("UniFi URL  (--unifi-url, UNIFI_URL env var, or config file unifi.url)")
    if not values["unifi_key"]:
        missing.append("UniFi API key  (UNIFI_API_KEY env var or config file unifi.api_key)")
    if not values["ipam_base_url"]:
        missing.append("phpIPAM base URL  (--ipam-base-url, IPAM_BASE_URL env var, or config file ipam.base_url)")
    if not values["ipam_app_id"]:
        missing.append("phpIPAM App ID  (--ipam-app-id, IPAM_APP_ID env var, or config file ipam.app_id)")
    if not values["ipam_key"]:
        missing.append("phpIPAM API key  (IPAM_API_KEY env var or config file ipam.api_key)")

    if missing:
        logging.error("Missing required configuration:")
        for item in missing:
            logging.error(f"  - {item}")
        raise SystemExit(1)

    include_subnets = parse_subnets(values["include_subnets"])
    exclude_subnets = parse_subnets(values["exclude_subnets"])

    if include_subnets:
        logging.info(f"Subnet filter: include only {[str(s) for s in include_subnets]}")
    elif exclude_subnets:
        logging.info(f"Subnet filter: exclude {[str(s) for s in exclude_subnets]}")

    if values["insecure"]:
        logging.warning("SSL certificate verification is disabled (--insecure).")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    assert ipam_url is not None  # validated above; both ipam_base_url and ipam_app_id are set
    return Config(
        unifi_url=values["unifi_url"],
        unifi_key=values["unifi_key"],
        ipam_url=ipam_url,
        ipam_key=values["ipam_key"],
        verify_ssl=not values["insecure"],
        include_subnets=include_subnets,
        exclude_subnets=exclude_subnets,
    )


def xmit(cfg: Config, service, endpoint, params=None, method="get") -> dict:
    """
    Abstracted helper function to send requests to either the UniFi or phpIPAM API.

    Args:
        cfg (Config): The active configuration object.
        service (str): The target service, either 'unifi' or 'ipam'.
        endpoint (str): The specific API endpoint to target (e.g., 'sites').
        params (dict, optional): A dictionary of parameters. Used as query params for GET
            or as the JSON body for POST/PATCH. Defaults to None.
        method (str, optional): The HTTP method to use. Defaults to "get".

    Returns:
        dict: The JSON response from the API as a dictionary, or {} on failure.
    """
    if service == "unifi":
        headers = {"X-API-Key": cfg.unifi_key, "Content-Type": "application/json"}
        base_url = cfg.unifi_url
    elif service == "ipam":
        headers = {"token": cfg.ipam_key, "Content-Type": "application/json"}
        base_url = cfg.ipam_url
    else:
        raise ValueError("Invalid service specified. Use 'unifi' or 'ipam'")

    try:
        requests_method = getattr(requests, method.lower())
        kwargs = {"headers": headers, "verify": cfg.verify_ssl, "timeout": 10}

        if method.lower() == "get":
            kwargs["params"] = params
        elif method.lower() in ["post", "patch", "put"]:
            kwargs["json"] = params

        url = f"{base_url.rstrip('/')}/{endpoint}"
        logging.debug(f"{method.upper()} {url}")

        response = requests_method(url, **kwargs)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as errh:
        if errh.response is not None:
            try:
                error_body = errh.response.json()
                if errh.response.status_code >= 500:
                    # Server-side errors are always unexpected — log loudly.
                    logging.error(f"HTTP server error {errh.response.status_code}: {error_body.get('message', errh)}")
                else:
                    # 4xx errors are client-level conditions (not found, conflict, etc.)
                    # — log at debug and return the body so callers can handle them.
                    logging.debug(f"HTTP {errh.response.status_code}: {error_body.get('message', '')} ({errh.response.url})")
                return error_body
            except ValueError:
                logging.error(f"HTTP error: {errh}")
                logging.error(f"Response body: {errh.response.text}")
        else:
            logging.error(f"HTTP error: {errh}")
    except AttributeError:
        logging.error(f"Invalid or unsupported HTTP method '{method}'")
    except requests.exceptions.RequestException as err:
        logging.error(f"Request failed: {err}")

    return {}


def nuke_ipam_addresses(cfg: Config) -> bool:
    """
    Deletes all existing address records from all subnets found in phpIPAM.
    This is a destructive operation used for the --nuke-and-pave mode.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logging.info("--- STARTING NUKE PHASE ---")

    subnets = xmit(cfg, "ipam", "subnets")

    if not subnets.get("success"):
        logging.error("Unable to retrieve subnets from phpIPAM. Nuke operation aborted.")
        return False

    for subnet in subnets["data"]:
        subnet_id = subnet["id"]
        logging.info(f"Truncating subnet {subnet_id} ({subnet['subnet']})")
        nuke = xmit(cfg, "ipam", f"subnets/{subnet_id}/truncate/", method="delete")
        if nuke and nuke.get("success"):
            logging.info(f"Subnet {subnet_id} cleared.")
        else:
            logging.error(f"Failed to clear subnet {subnet_id}. Response: {nuke}")

    return True


def create_new_address(cfg: Config, ip, mac, hostname, payload=None) -> bool:
    """
    Creates a new address record in phpIPAM. It first finds the most
    specific containing subnet for the given IP address.

    Args:
        cfg (Config): The active configuration object.
        ip (str): The IP address for the new record.
        mac (str): The MAC address for the new record.
        hostname (str): The hostname for the new record.
        payload (dict, optional): Existing record fields to preserve on re-create.

    Returns:
        bool: True if the address was successfully created, False otherwise.
    """
    subnet_response = xmit(cfg, "ipam", f"subnets/overlapping/{ip}/32")
    if not subnet_response or not subnet_response.get("data"):
        logging.error(f"No containing subnet found for {ip}. Cannot create address.")
        return False

    subnet_id = subnet_response["data"][0]["id"]

    if payload:
        create_payload = {
            "ip": ip,
            "subnetId": subnet_id,
            "mac": mac,
            "note": f"{payload.get('note', '')} Updated by UniFi2IPAM".strip(),
        }
        # Preserve custom fields from the existing record, excluding system-managed ones.
        for key, value in payload.items():
            if key not in {"id", "subnetId", "ip", "mac", "location", "note",
                           "firewallAddressObject", "editDate", "customer_id"}:
                create_payload[key] = value
    else:
        create_payload = {
            "ip": ip,
            "subnetId": subnet_id,
            "hostname": hostname,
            "mac": mac,
            "note": "Created by UniFi2IPAM",
            "description": "",
        }

    create_response = xmit(cfg, "ipam", "addresses", params=create_payload, method="post")

    if create_response and create_response.get("success"):
        logging.info(f"Created address {ip} (MAC {mac})")
        return True

    # If phpIPAM reported a conflict, find and remove the stale record then retry.
    # This handles devices that changed MAC but kept the same IP.
    if "already exists" in (create_response.get("message") or "").lower():
        existing = xmit(cfg, "ipam", f"addresses/search/{ip}/")
        if existing and existing.get("data"):
            conflict_id = existing["data"][0]["id"]
            conflict_mac = existing["data"][0].get("mac", "unknown")
            logging.warning(
                f"IP {ip} already exists (record {conflict_id}, MAC {conflict_mac}) — "
                f"removing stale record and retrying"
            )
            remove = xmit(cfg, "ipam", f"addresses/{conflict_id}/", method="delete")
            if remove and remove.get("success"):
                create_response = xmit(cfg, "ipam", "addresses", params=create_payload, method="post")
                if create_response and create_response.get("success"):
                    logging.info(f"Created address {ip} (MAC {mac}) after resolving conflict")
                    return True
            else:
                logging.error(f"Failed to remove stale record {conflict_id} for IP {ip}")

    msg = create_response.get("message") if create_response else "No response"
    logging.error(f"Failed to create address {ip} (MAC {mac}): {msg}")
    return False


def sync_phpipam_by_mac(cfg: Config, ip, mac, hostname) -> None:
    """
    Finds a device by its MAC address in phpIPAM and updates its IP and hostname.
    If not found, creates a new address record.

    The IP update is handled as create-then-delete: the new record is created first,
    and the old one is only removed after the new one is confirmed. This avoids a
    window where no record exists if the create step fails.

    Args:
        cfg (Config): The active configuration object.
        ip (str): The current IP address of the device from UniFi.
        mac (str): The MAC address of the device, used as the primary key.
        hostname (str): The current hostname of the device from UniFi.
    """
    response = xmit(cfg, "ipam", f"addresses/search_mac/{mac}/")

    if not response or not response.get("data"):
        logging.info(f"MAC {mac} not found in phpIPAM — creating new entry")
        create_new_address(cfg, ip, mac, hostname)
        return

    existing_record = response["data"][0]
    record_id = existing_record["id"]
    existing_ip = existing_record["ip"]

    if existing_ip == ip:
        logging.info(f"MAC {mac} already has correct IP {ip} — no update needed")
        return

    logging.info(f"MAC {mac} (record {record_id}): IP changed {existing_ip} → {ip}")

    # Create the new record first; only delete the old one if that succeeds.
    success = create_new_address(cfg, ip, mac, hostname, payload=existing_record)
    if success:
        remove = xmit(cfg, "ipam", f"addresses/{record_id}/", method="delete")
        if not remove or not remove.get("success"):
            logging.warning(
                f"New record created for {mac} but failed to delete old record {record_id}"
            )
    else:
        logging.error(
            f"Failed to create new record for {mac}; old record {record_id} preserved"
        )


def select_site_id(sites) -> str:
    """
    Prompts the user to select a site from the available sites in the UniFi API.
    Exits if no valid choice is made.

    Args:
        sites (dict): The JSON response from the UniFi API containing site data.

    Returns:
        str: The ID of the selected site.
    """
    print("===== Available sites =====")
    for i, site in enumerate(sites.get("data", []), start=1):
        print(f"{i} ---> Site Name: {site['name']}, ID: {site['id']}")
    print("===========================\n")

    count = len(sites.get("data", []))
    choice = input(f"Select a site by number (1-{count}) or press Enter for the first: ")

    if choice.isdigit() and 1 <= int(choice) <= count:
        return sites["data"][int(choice) - 1]["id"]

    logging.warning("No valid choice made. Exiting.")
    raise SystemExit(0)


def get_unifi_clients(cfg: Config, limit, site_arg=None) -> list:
    """
    Fetches the list of clients from the UniFi API.

    Args:
        cfg (Config): The active configuration object.
        limit (int): Maximum number of clients to fetch.
        site_arg (str, optional): A specific site ID to use directly.

    Returns:
        list: A list of client dictionaries from the UniFi API.
    """
    if site_arg:
        logging.info(f"Using specified site ID: {site_arg}")
        client_list = xmit(cfg, "unifi", f"sites/{site_arg}/clients", params={"limit": limit})
    else:
        logging.info("Fetching sites from UniFi API...")
        sites = xmit(cfg, "unifi", "sites")

        if not sites or len(sites.get("data", [])) == 0:
            logging.error("No sites found or unable to retrieve site data.")
            raise SystemExit(1)

        if len(sites.get("data", [])) > 1:
            site_id = select_site_id(sites)
        else:
            site_id = sites["data"][0]["id"]
            logging.info(f"One site found — using site ID: {site_id}")

        logging.info("Fetching clients from UniFi API...")
        client_list = xmit(cfg, "unifi", f"sites/{site_id}/clients", params={"limit": limit})

    if client_list and client_list.get("data"):
        return client_list["data"]

    logging.error("No clients found or unable to retrieve client data.")
    raise SystemExit(1)


def process_client(cfg: Config, nuke_and_pave: bool, client: dict) -> None:
    """
    Process a single UniFi client — either pave (create) or sync it in phpIPAM.
    Designed to be called from a thread pool.

    Args:
        cfg (Config): The active configuration object.
        nuke_and_pave (bool): If True, always create a new record (pave mode).
        client (dict): A single client dict from the UniFi API.
    """
    if "ipAddress" not in client or "macAddress" not in client:
        logging.debug(f"Client missing IP or MAC — skipping: {json.dumps(client)}")
        return

    ip = client["ipAddress"]
    mac = client["macAddress"]
    hostname = client.get("name", "Unknown")

    if not is_in_filter(cfg, ip):
        logging.debug(f"Skipping MAC {mac} (IP: {ip}) — filtered by subnet configuration")
        return

    if nuke_and_pave:
        logging.info(f"Paving MAC {mac} (IP: {ip})")
        create_new_address(cfg, ip, mac, hostname)
    else:
        logging.info(f"Syncing MAC {mac} (IP: {ip})")
        sync_phpipam_by_mac(cfg, ip, mac, hostname)


def do_dry_run(cfg: Config, args) -> None:
    """
    Fetch UniFi clients and log what would be synced without touching phpIPAM.

    Args:
        cfg (Config): The active configuration object.
        args: Parsed command-line arguments.
    """
    logging.info("Dry run mode — no changes will be made to phpIPAM.")

    if args.nuke_and_pave:
        logging.warning("--nuke-and-pave is set but has no effect in dry run mode.")

    clients = get_unifi_clients(cfg, args.limit, args.site_id)
    logging.info(f"Found {len(clients)} clients in UniFi.")

    for client in clients:
        if "ipAddress" not in client or "macAddress" not in client:
            logging.debug(f"Client missing IP or MAC: {json.dumps(client)}")
            continue

        ip = client["ipAddress"]
        mac = client["macAddress"]
        hostname = client.get("name", "Unknown")

        if not is_in_filter(cfg, ip):
            logging.debug(f"Would skip MAC {mac} (IP: {ip}) — filtered by subnet configuration")
        else:
            logging.info(f"Would sync MAC {mac} (IP: {ip}, hostname: {hostname})")

    logging.info("Dry run complete.")


def main(cfg: Config, args) -> None:
    """Main execution flow."""

    if args.dryrun:
        do_dry_run(cfg, args)
        return

    if args.nuke_and_pave:
        print("====== WARNING! ======")
        print("Nuke and pave mode will delete ALL existing addresses in ALL subnets in phpIPAM.")
        check = input("Type 'yes' to confirm: ")
        if check.lower() != "yes":
            logging.info("Nuke and pave cancelled.")
            return

        if not nuke_ipam_addresses(cfg):
            logging.error("Nuke phase failed. Aborting.")
            raise SystemExit(1)
        logging.info("Nuke phase complete.")

    clients = get_unifi_clients(cfg, args.limit, args.site_id)
    logging.info(f"Found {len(clients)} clients. Processing with {args.workers} workers...")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_client, cfg, args.nuke_and_pave, client): client
            for client in clients
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Unhandled error processing client: {e}")

    logging.info("Sync complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sync UniFi clients to phpIPAM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Configuration precedence (lowest to highest):\n"
            f"  config file ({DEFAULT_CONFIG_PATH})\n"
            "  environment variables\n"
            "  CLI flags\n\n"
            "Required env vars:  UNIFI_API_KEY, IPAM_API_KEY\n"
            "Optional env vars:  UNIFI_URL, IPAM_BASE_URL, IPAM_APP_ID"
        ),
    )

    # Operational flags
    parser.add_argument(
        "--nuke-and-pave",
        action="store_true",
        help="Delete all addresses in IPAM before paving with UniFi clients.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum number of clients to fetch from UniFi (default: 1000).",
    )
    parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        metavar="ID",
        help="UniFi site ID to use. If omitted, available sites are listed for selection.",
    )
    parser.add_argument(
        "--dryrun",
        action="store_true",
        help="Preview what would be synced without making any changes to phpIPAM.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel workers for client processing (default: 4).",
    )

    # Configuration sources
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="PATH",
        help=f"Path to YAML config file (default: {DEFAULT_CONFIG_PATH}).",
    )
    parser.add_argument(
        "--unifi-url",
        type=str,
        default=None,
        metavar="URL",
        help="UniFi controller base URL. Overrides UNIFI_URL env var and config file.",
    )
    parser.add_argument(
        "--ipam-base-url",
        type=str,
        default=None,
        metavar="URL",
        help="phpIPAM base URL. Overrides IPAM_BASE_URL env var and config file.",
    )
    parser.add_argument(
        "--ipam-app-id",
        type=str,
        default=None,
        metavar="ID",
        help="phpIPAM application ID. Overrides IPAM_APP_ID env var and config file.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification. Use for self-signed certificates.",
    )
    parser.add_argument(
        "--include-subnet",
        action="append",
        default=[],
        metavar="CIDR",
        help="Only process clients whose IP falls within this subnet. "
             "May be repeated. Mutually exclusive with --exclude-subnet.",
    )
    parser.add_argument(
        "--exclude-subnet",
        action="append",
        default=[],
        metavar="CIDR",
        help="Skip clients whose IP falls within this subnet. "
             "May be repeated. Mutually exclusive with --include-subnet.",
    )

    # Logging flags
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level output.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress all output except errors.",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        metavar="PATH",
        help="Write log output to this file in addition to stdout.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="unifi2ipam v1.1.0",
    )

    args = parser.parse_args()
    setup_logging(args)
    cfg = load_config(args)
    main(cfg, args)
