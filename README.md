# unifi2ipam

Synchronizes network client data from a UniFi Network Controller to a [phpIPAM](https://phpipam.net/) instance. The script reads all active clients from a UniFi site and creates or updates their address records in phpIPAM, using the MAC address as the stable identifier across IP changes.

> **Warning:** This script makes destructive changes to phpIPAM. The `--nuke-and-pave` mode in particular will delete **all address records in all subnets** before rebuilding from UniFi data. Use with caution. ***No warranty is provided.***

---

## How It Works

### Sync Mode (default)

For each client reported by UniFi that has both an IP and MAC address:

1. phpIPAM is searched for an existing record with that MAC address.
2. **If not found:** a new address record is created. The script first identifies the most specific subnet in phpIPAM that contains the client's IP (using the `subnets/overlapping` endpoint), then `POST`s the new record into that subnet.
3. **If found and the IP matches:** no change is made.
4. **If found and the IP has changed:** the new record is created first, then the old one is deleted only after the new one is confirmed. This avoids a window where no record exists if the create step fails. Custom fields (hostname, description, owner, etc.) are preserved from the original record.

> phpIPAM does not support changing the IP address of an existing record, so IP changes are handled as a create-then-delete.

### Nuke and Pave Mode (`--nuke-and-pave`)

A full rebuild intended for initial setup or disaster recovery:

1. Prompts for interactive confirmation before making any changes.
2. Fetches all subnets from phpIPAM and calls the `truncate` endpoint on each one, deleting every address record.
3. Creates fresh records for all UniFi clients in parallel.

### Dry Run Mode (`--dryrun`)

Connects to UniFi and lists all clients that *would* be synced, without touching phpIPAM. Useful for verifying connectivity and reviewing what the script will do before the first live run.

---

## Prerequisites

- Python 3.10 or later
- [uv](https://docs.astral.sh/uv/) for dependency management
- A UniFi Network Controller with API access enabled
- A phpIPAM instance with an API application configured

---

## Installation

```bash
git clone https://github.com/<you>/unifi2ipam.git
cd unifi2ipam
uv sync
```

---

## Configuration

Configuration is loaded from three sources in order of increasing precedence:

```text
config file  →  environment variables  →  CLI flags
```

### Config file (recommended)

Default location: `/etc/unifi2ipam/config.yaml`
Override with: `--config PATH`

```yaml
unifi:
  url: "https://unifi.local/proxy/network/integration/v1/"
  # api_key: "..."  # use UNIFI_API_KEY env var instead

ipam:
  base_url: "https://ipam.local"
  app_id: "your_app_id"
  # api_key: "..."  # use IPAM_API_KEY env var instead

# insecure: true  # uncomment to disable SSL certificate verification
```

### Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `UNIFI_API_KEY` | Yes | UniFi API key |
| `IPAM_API_KEY` | Yes | phpIPAM application token |
| `UNIFI_URL` | No* | UniFi controller base URL |
| `IPAM_BASE_URL` | No* | phpIPAM host URL |
| `IPAM_APP_ID` | No* | phpIPAM application ID |

*Required if not set in config file or via CLI flags.

### CLI flags

| Flag | Description |
| --- | --- |
| `--unifi-url URL` | UniFi controller base URL |
| `--ipam-base-url URL` | phpIPAM base URL |
| `--ipam-app-id ID` | phpIPAM application ID |
| `--insecure` | Disable SSL certificate verification (opt-in, for self-signed certs) |
| `--config PATH` | Path to YAML config file |

---

### Generating a UniFi API Key

Log in to the UniFi dashboard with a sufficiently privileged account and go to **Settings → Control Plane → Integrations**. Click **Create API Key**, give it a name, set an optional expiry, and copy the key. Use this as `UNIFI_API_KEY`.

The UniFi API endpoint is typically: `https://<controller-ip>/proxy/network/integration/v1/`

### Generating a phpIPAM API Token

Log in as an Administrator and go to **Administration → API → Create API key**. Set an App ID (this becomes `IPAM_APP_ID`), copy the generated App code, and set the security mode to **SSL with App code token**. Use the App code as `IPAM_API_KEY`.

---

## Usage

```bash
# Verify connectivity and preview what would be synced (no changes made)
uv run unifi2ipam.py --dryrun

# Standard incremental sync
uv run unifi2ipam.py

# Use self-signed certificates
uv run unifi2ipam.py --insecure

# Specify a site directly (skips the interactive site-selection prompt)
uv run unifi2ipam.py --site-id <site-id>

# Full rebuild — deletes all phpIPAM addresses before re-creating from UniFi
uv run unifi2ipam.py --nuke-and-pave

# Verbose output (shows each API request)
uv run unifi2ipam.py --dryrun --verbose

# Quiet mode (errors only) with log file
uv run unifi2ipam.py --quiet --log-file /var/log/unifi2ipam.log
```

Full option reference (`uv run unifi2ipam.py --help`):

```text
options:
  --nuke-and-pave      Delete all addresses in IPAM before paving with UniFi clients.
  --limit LIMIT        Maximum number of clients to fetch from UniFi (default: 1000).
  --site-id ID         UniFi site ID. If omitted, available sites are listed for selection.
  --dryrun             Preview what would be synced without touching phpIPAM.
  --workers WORKERS    Parallel workers for client processing (default: 4).
  --config PATH        Path to YAML config file.
  --unifi-url URL      UniFi controller base URL.
  --ipam-base-url URL  phpIPAM base URL.
  --ipam-app-id ID     phpIPAM application ID.
  --insecure           Disable SSL certificate verification.
  --verbose            Enable debug-level output.
  --quiet              Suppress all output except errors.
  --log-file PATH      Write logs to file in addition to stdout.
  --version            Show version and exit.
```

---

## Cron Job Setup

For automated periodic syncs, add an entry to your crontab. Use `--site-id` to avoid the interactive site-selection prompt and `--quiet` to limit output to errors only:

```cron
# Sync UniFi clients to phpIPAM every hour
0 * * * * UNIFI_API_KEY=your_key IPAM_API_KEY=your_key /path/to/uv run /path/to/unifi2ipam/unifi2ipam.py --site-id <site-id> --quiet --log-file /var/log/unifi2ipam.log 2>&1
```

Find your site ID with `uv run unifi2ipam.py --dryrun` first.

---

## Container Deployment

Pre-built images are published to the GitHub Container Registry on every push to `main` and on version tags:

```text
ghcr.io/adamherbert/unifi2ipam:main      # latest from main
ghcr.io/adamherbert/unifi2ipam:1.0.1     # specific version
```

### Docker

Pass credentials as environment variables and mount your `config.yaml`:

```bash
docker run --rm \
  -e UNIFI_API_KEY=your_unifi_key \
  -e IPAM_API_KEY=your_ipam_key \
  -v /path/to/config.yaml:/etc/unifi2ipam/config.yaml:ro \
  ghcr.io/adamherbert/unifi2ipam:main \
  --site-id <site-id> --quiet
```

### Kubernetes CronJob

Create a `Secret` for credentials and a `ConfigMap` for the config file, then deploy as a `CronJob`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: unifi2ipam-secrets
  namespace: unifi2ipam
type: Opaque
stringData:
  UNIFI_API_KEY: "your_unifi_api_key"
  IPAM_API_KEY: "your_ipam_api_key"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: unifi2ipam-config
  namespace: unifi2ipam
data:
  config.yaml: |
    unifi:
      url: "https://unifi.local/proxy/network/integration/v1/"
    ipam:
      base_url: "https://ipam.local"
      app_id: "your_app_id"
    # insecure: true
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: unifi2ipam
  namespace: unifi2ipam
spec:
  schedule: "0 * * * *"          # every hour
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: unifi2ipam
              image: ghcr.io/adamherbert/unifi2ipam:main
              args: ["--site-id", "<site-id>", "--quiet"]
              env:
                - name: UNIFI_API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: unifi2ipam-secrets
                      key: UNIFI_API_KEY
                - name: IPAM_API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: unifi2ipam-secrets
                      key: IPAM_API_KEY
              volumeMounts:
                - name: config
                  mountPath: /etc/unifi2ipam
                  readOnly: true
          volumes:
            - name: config
              configMap:
                name: unifi2ipam-config
```

Find your site ID first using a dry run (replace image pull with your actual values):

```bash
docker run --rm \
  -e UNIFI_API_KEY=your_key \
  -e IPAM_API_KEY=your_key \
  -v /path/to/config.yaml:/etc/unifi2ipam/config.yaml:ro \
  ghcr.io/adamherbert/unifi2ipam:main --dryrun
```

---

## Notes

- SSL certificate verification is **enabled by default**. Use `--insecure` (or `insecure: true` in the config file) for self-signed certificates.
- Only clients with both `ipAddress` and `macAddress` fields populated are processed. Clients without a DHCP lease are skipped.
- Subnets must already exist in phpIPAM. The script will not create subnets — if no matching subnet is found for a client's IP, that client is skipped with an error message.
- Client processing is parallelised using a thread pool (`--workers`, default 4). `nuke_ipam_addresses` runs sequentially.

---

## To Do

- [ ] Log output to a file rather than stdout only *(use `--log-file` as a workaround)*

## Problems

Please open a [GitHub Issue](../../issues) and it will be addressed as time permits.
