#!/usr/bin/env python3

# Synchronize network client information from a UniFi Network Controller to a phpIPAM instance.

# This script can operate in two modes:
# 1. Sync Mode (default): Updates phpIPAM based on MAC addresses. If a device is found,
#     it's updated. If not, it's created.
# 2. Nuke and Pave Mode (--nuke-and-pave): Deletes all addresses in all configured
#     subnets in phpIPAM and then creates fresh records for every client found in UniFi.

# Required Environment Variables:
# - UNIFI_API_KEY: Your API key for the UniFi Network Controller.
# - IPAM_API_KEY: Your API key for the phpIPAM application.

import argparse
import json
import os

import requests
import urllib3

# Disable warnings for self-signed certificates, common in local network setups.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
# These URLs should be updated to match your specific UniFi and phpIPAM instances.
UNIFI_URL = "https://example.com-or-unifi.ip/proxy/network/integration/v1/"
IPAM_APP_ID = "example_app_id"  # Replace with your phpIPAM application ID.
IPAM_URL = f"https://example.com/api/{IPAM_APP_ID}/"
# Sensitive keys are read from environment variables for security.
UNIFI_KEY = os.environ.get("UNIFI_API_KEY")
IPAM_KEY = os.environ.get("IPAM_API_KEY")
# ---------------------


def xmit(service, endpoint, params=None, method="get") -> dict:
    """
    Abstracted helper function to send requests to either the UniFi or phpIPAM API.

    Args:
        service (str): The target service, either 'unifi' or 'ipam'.
        endpoint (str): The specific API endpoint to target (e.g., 'sites').
        params (dict, optional): A dictionary of parameters. Used as query params for GET
            or as the JSON body for POST/PATCH. Defaults to None.
        method (str, optional): The HTTP method to use. Defaults to "get".

    Returns:
        dict: The JSON response from the API as a dictionary, or None on failure.
    """

    # Set the base URL and authentication headers based on the target service.
    if service == "unifi":
        # The modern UniFi API uses a Bearer token.
        headers = {"X-API-Key": UNIFI_KEY, "Content-Type": "application/json"}
        base_url = UNIFI_URL
    elif service == "ipam":
        # phpIPAM uses a custom 'token' header.
        headers = {"token": IPAM_KEY, "Content-Type": "application/json"}
        base_url = IPAM_URL
    else:
        raise ValueError("Invalid service specified. Use 'unifi' or 'ipam'")

    try:
        # Dynamically get the appropriate function from the requests module (e.g., requests.get).
        requests_method = getattr(requests, method.lower())

        # Prepare keyword arguments for the request call.
        kwargs = {"headers": headers, "verify": False, "timeout": 10}

        # Conditionally add the correct payload argument based on the HTTP method.
        if method.lower() == "get":
            kwargs["params"] = params
        elif method.lower() in ["post", "patch", "put"]:
            kwargs["json"] = params

        # Ensure the URL is constructed correctly, avoiding double slashes
        if base_url.endswith("/"):
            url = f"{base_url}{endpoint}"
        else:
            url = f"{base_url}/{endpoint}"

        # Make the API call by unpacking the kwargs dictionary.
        response = requests_method(url, **kwargs)

        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as errh:
        if 'search_mac' not in errh.response.url:
            print(f"Http Error: {errh}")
            print(f"Response Body: {response.text}")
    except AttributeError:
        print(f"Error: Invalid or unsupported HTTP method '{method}'")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")
    return None


def nuke_ipam_addresses() -> bool:
    """
    Deletes all existing address records from all subnets found in phpIPAM.
    This is a destructive operation used for the --nuke-and-pave mode.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    print(f"\n--- STARTING NUKE PHASE ---")

    # First, get a list of all subnets from phpIPAM.
    subnets = xmit("ipam", "subnets")

    if subnets.get("success"):
        for subnet in subnets["data"]:
            subnet_id = subnet["id"]
            print(f"Found Subnet ID: {subnet_id} for CIDR {subnet['subnet']}")

            # Use the dedicated 'truncate' API endpoint for efficiency.
            print("--- Deleting all addresses in this subnet ---")
            nuke = xmit("ipam", f"subnets/{subnet_id}/truncate/", method="delete")
            if nuke and nuke.get("success"):
                print(f"Successfully deleted all addresses in subnet {subnet_id}.")
            else:
                print(
                    f"Failed to delete addresses in subnet {subnet_id}. Response: {nuke}"
                )
    else:
        print("Error: Unable to retrieve subnets from phpIPAM. Nuke operation aborted.")
        exit(1)
    return True


def sync_phpipam_by_mac(ip, mac, hostname) -> None:
    """
    Finds a device by its MAC address in phpIPAM and updates its IP and hostname.
    If not found, it triggers the creation of a new address record.
    This is the default sync logic for cron jobs.

    Args:
        ip (str): The current IP address of the device from UniFi.
        mac (str): The MAC address of the device, used as the primary key.
        hostname (str): The current hostname of the device from UniFi.
    """
    # Step 1: Search for the device by its MAC address.
    response = xmit("ipam", f"addresses/search_mac/{mac}/")

    # Step 2: If the MAC is not found, response will be None (due to 404 error handling in xmit).
    if response is None:
        print(
            f"phpIPAM: MAC address {mac} not found, attempting to create new entry..."
        )
        create_new_address(ip, mac, hostname)
        return

    # If the MAC was found, proceed to update the existing record.
    existing_record = response["data"][0]
    record_id = existing_record["id"]
    existing_ip = existing_record["ip"]

    # To be efficient, only update if the IP address has actually changed.
    if existing_ip == ip:
        print(
            f"phpIPAM: Existing record for MAC {mac} already has the correct IP {ip}. No update needed."
        )
        return

    print(
        f"phpIPAM: Found existing record for MAC {mac} (ID: {record_id}). Updating..."
    )

    # Since updating IP address isn't possible with phpIPAM, we delete the record and create a new one.
    remove_ip = xmit("ipam", f"addresses/{record_id}/", method="delete")

    if not remove_ip.get("success"):
        print(f"phpIPAM: Failed to update (delete action) existing record {record_id}.")

    create_new_address(ip, mac, hostname, payload=existing_record)


def create_new_address(ip, mac, hostname, payload=None) -> None:
    """
    Creates a new address record in phpIPAM. It first finds the most
    specific containing subnet for the given IP address.

    Args:
        ip (str): The IP address for the new record.
        mac (str): The MAC address for the new record.
        hostname (str): The hostname for the new record.
        payload (dict, optional): Additional parameters for the address creation.
            Defaults to None, but can be used to pass extra data if needed.
    """

    # Step 1: Use the 'overlapping' endpoint to find the most specific subnet for the IP.
    # The '/32' indicates we are searching for a single host address.
    subnet_search_url = xmit("ipam", f"subnets/overlapping/{ip}/32")
    if not subnet_search_url or not subnet_search_url.get("data"):
        # If no subnet found, we cannot create the address.
        print(f"phpIPAM: No containing subnet found for {ip}. Cannot create address.")
        return

    subnet_id = subnet_search_url["data"][0]["id"]

    # Step 2: Create or update the address with the found subnet ID.
    if payload:
        create_payload = {
            "ip": ip,
            "subnetId": subnet_id,
            "mac": mac,
            "note": f"{payload.get('note', '')} Updated by UniFi2IPAM",
        }

        # Only send the information back to phpIPAM that the API supports and we don't want changed.
        for key, value in payload.items():
            if key not in [
                "id",
                "subnetId",
                "ip",
                "mac",
                "location",
                "note",
                "firewallAddressObject",
                "editDate",
                "customer_id",
            ]:
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

    # Step 3: Send the request to create the address in phpIPAM.
    create_response = xmit("ipam", "addresses", params=create_payload, method="post")

    if create_response.get("success"):
        print(f"phpIPAM: Successfully created address for {ip} with MAC {mac}.")
    else:
        print(
            f"phpIPAM: Failed to create address. Message: {create_response.get('message')}"
        )


def select_site_id(sites) -> str:
    """
    Prompts the user to select a site from the available sites in the UniFi API.
    If the user does not make a valid choice, exit the script.

    Args:
        sites (dict): The JSON response from the UniFi API containing site data.

    Returns:
        str: The ID of the selected site.
    """
    # Select the correct site
    counter = 0
    print(f"===== Available sites =====")

    for site in sites.get("data", []):
        counter += 1
        print(f"{counter} ---> Site Name: {site['name']}, ID: {site['id']}")

    print(f"===========================\n")

    choice = input(
        f"Please select a site by number (1-{counter}) or press Enter to use the first site: "
    )

    if choice.isdigit() and 1 <= int(choice) <= counter:
        site_id = sites["data"][int(choice) - 1]["id"]
        return site_id
    else:
        print("No valid choice made. Exiting...")
        exit(0)


def get_unifi_clients(limit, site_arg=None) -> list:
    """
    Fetches the list of clients from the UniFi API, allowing for site selection if multiple sites are available.

    Returns:
        list: A list of client dictionaries retrieved from the UniFi API.
    """

    if site_arg:
        # If a specific site ID is provided, use it directly.
        print(f"Using specified site ID: {site_arg}")
        client_list = xmit(
            "unifi", f"sites/{site_arg}/clients", params={"limit": limit}
        )
    else:
        # Fetch the available sites from the UniFi API.
        print("Fetching sites from UniFi API...")
        sites = xmit("unifi", "sites")

        if not sites or len(sites.get("data")) == 0:
            print("Error: No sites found or unable to retrieve site data.")
            exit(1)

        # If there are multiple sites, prompt the user to select one.
        if len(sites.get("data")) > 1:
            site_id = select_site_id(sites)
            print(f"Using site ID: {site_id}")
        else:
            site_id = sites["data"][0]["id"]
            print(f"Only one site found. Using site ID: {site_id}")

        # Fetch all clients from the determined site.
        print("Fetching clients from UniFi API...")
        client_list = xmit("unifi", f"sites/{site_id}/clients", params={"limit": limit})

    # Check if the client list was successfully retrieved.
    if client_list and client_list.get("data"):
        return client_list["data"]
    else:
        print("Error: No clients found or unable to retrieve client data.")
        exit(1)


def do_dry_run(args) -> None:
    """
    Perform a dry run of the script without making any changes to phpIPAM.
    This is useful for testing the script's functionality without affecting the actual data.

    Args:
        args: The command-line arguments passed to the script.
    """

    print("Running in dry run mode. No changes will be made to phpIPAM.")
    print("This is useful for testing the script without making actual changes.")

    if args.nuke_and_pave:
        print(
            "Warning: Nuke and pave mode is enabled, but in dry run mode, no changes will be made."
        )
        print(
            "This means that even if you specify --nuke-and-pave, it will not delete any addresses in phpIPAM."
        )

    clients = get_unifi_clients(args.limit, args.site_id)

    print(f"Found {len(clients)} clients in UniFi.")
    print("Processing clients in dry run mode...")

    for client in clients:
        if "ipAddress" in client and "macAddress" in client:
            ip = client["ipAddress"]
            mac = client["macAddress"]
            hostname = client.get("name", "Unknown")
            print(
                f"DRY RUN: Would attempt to sync MAC {mac} (IP: {ip}, Hostname: {hostname})"
            )
        else:
            print("ERROR! Client data is missing 'ipAddress' or 'macAddress' fields.")
            print(json.dumps(client, indent=2))

    print("Dry run completed. No changes made to phpIPAM.")


def main(args):
    """Main function to handle the script's execution flow based on command-line arguments."""

    if args.dryrun:
        do_dry_run(args)
        return

    # If --nuke-and-pave is specified, ask for confirmation before proceeding.
    if args.nuke_and_pave:
        print("====== WARNING! ======")
        print(
            "Nuke and pave mode enabled. ALL existing addresses in phpIPAM will be deleted before syncing."
        )
        check = input(
            "Are you sure you want to proceed? This will delete ***ALL*** existing addresses in all subnets in phpIPAM. Type 'yes' to confirm: "
        )
        if check.lower() != "yes":
            print("Nuke and pave operation cancelled.")
            exit(0)

        # Execute the nuke operation.
        if not nuke_ipam_addresses():
            print("Nuke operation failed. Aborting script.")
            exit(1)
        print("Nuke operation completed successfully.")

    clients = get_unifi_clients(args.limit, args.site_id)

    print(f"Found {len(clients)} clients in UniFi.")
    print("Processing clients and adding to IPAM...")

    # Iterate through each client and sync it to phpIPAM.
    for client in clients:
        # Ensure the client has the necessary data before processing.
        if "ipAddress" in client and "macAddress" in client:
            ip = client["ipAddress"]
            mac = client["macAddress"]
            hostname = client.get("name", "Unknown")
        else:
            print("ERROR! Client data is missing 'ipAddress' or 'macAddress' fields.")
            print(json.dumps(client, indent=2))
            print("Skipping...")
            continue

        # If we're nuking and paving, there's no need to attempt to sync.
        if args.nuke_and_pave:
            print(f"--- Paving MAC {mac} (IP: {ip}) ---")
            create_new_address(ip, mac, hostname)
        else:
            print(f"--- Syncing MAC {mac} (IP: {ip}) ---")
            sync_phpipam_by_mac(ip, mac, hostname)

    # Final message indicating the sync process is complete.
    print("Sync completed.")


if __name__ == "__main__":
    # Set up the argument parser for command-line flags.
    parser = argparse.ArgumentParser(description="Sync UniFi clients to phpIPAM.")
    parser.add_argument(
        "--nuke-and-pave",
        action="store_true",
        help="Delete all addresses in IPAM before paving with UniFi clients.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Limit the number of clients to process (default: 1000).",
    )
    parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Specify a site ID to use for the UniFi API. If not provided, the script will prompt for site selection.",
    )
    parser.add_argument(
        "--dryrun",
        action="store_true",
        default=False,
        help="Perform a dry run without making any changes to phpIPAM. Useful for testing purposes.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="unifi2ipam v1.0.1",
        help="Show the version of the script.",
    )
    args = parser.parse_args()

    # --- Pre-flight Checks for required API keys ---
    if not UNIFI_KEY:
        print("Error: The UNIFI_API_KEY environment variable is not set.")
        print("Please set it before running the script, for example:")
        print("export UNIFI_API_KEY='your_api_key_here'")
        exit(1)

    if not IPAM_KEY:
        print("Error: The IPAM_API_KEY environment variable is not set.")
        print("Please set it before running the script, for example:")
        print("export IPAM_API_KEY='your_IPAM_API_KEY_here'")
        exit(1)

    for g in [UNIFI_URL, IPAM_URL, IPAM_APP_ID]:
        if "example" in g:
            print(
                f"Error: The IPAM_URL, UNIFI_URL, or APP_ID contains 'example'. Please update it to your actual values."
            )
            exit(1)

    main(args)
    # --- End of script ---
