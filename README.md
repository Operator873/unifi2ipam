# unifi2ipam
A handy script to assist with transferring the client list from UniFi gateway to phpIPAM. This script depends on API interactivity between the script and both the UniFi gateway and your phpIPAM installation. This will allow the clients visible to UniFi to be added to phpIPAM programmatically vs manually or by other means. Users can manually execute the script or configure it as a cron job.

## Installation
Clone this repository, verify execution ability (`chmod +x unifi2pam.py`), copy the script to a location of your choosing (*it's best to not leave it in the repo since you'll be editing the script with your homelab's information and don't want to lose that with updates*), update the URL and App Id variables in the script, and set your environmental variables (`UNIFI_API_KEY` and `IPAM_API_KEY`).

Finally, check function by executing `./unifi2ipam.py --help` to verify the script can execute.

As an optional step, create a link to use the script as a command. As a reminder, it's strongly encouraged to copy the script out of the repo vs editing the one in place to avoid inadvertantly losing configuration information.
```
$ sudo ln -s /path/to/your/unifi2ipam.py /usr/local/bin/unifi2ipam
```

## Updating
To update the script, you should update the repo on your local machine, then cp the new version of the script to your deployment location. You'll need to update the URLs for your UniFi device as well as the App ID and URL of your phpIPAM deployment.
```
$ cd /path/to/repo
$ git pull
$ cp /path/to/repo/unifi2ipam.py /path/to/your/scripts/unifi2ipam.py
$ vim /path/to/your/scripts/unifi2ipam.py
```

## Usage
Running the script without any options will attempt to sync changes to DHCP networks based on the mac address of the clients reported by UniFi. Using the `--nuke-and-pave` option will delete **ALL ADDRESSES** from **ALL SUBNETS** and then rebuild your IPAM with all the actively connected clients. ***Use with caution!!***
```
$ ./unifi2ipam.py --help
usage: unifi2ipam.py [-h] [--nuke-and-pave] [--limit LIMIT] [--site-id SITE_ID] [--dryrun] [--version]

Sync UniFi clients to phpIPAM.

options:
  -h, --help         show this help message and exit
  --nuke-and-pave    Delete all addresses in IPAM before paving with UniFi clients.
  --limit LIMIT      Limit the number of clients to process (default: 1000).
  --site-id SITE_ID  Specify a site ID to use for the UniFi API. If not provided, the script will prompt for site selection.
  --dryrun           Perform a dry run without making any changes to phpIPAM. Useful for testing purposes.
  --version          Show the version of the script.
  ```

  ## Configuration
  ### UniFi
  UniFi devices have an API available for use typically at `https://.../proxy/network/integration/v1/` which will need to be added to the script in the Configuration section (`UNIFI_URL`). You'll need to generate an API key within the UniFi dashboard by logging in with a sufficiently privileged account, and going to `Settings > Control Plane > Integrations`. Then add an API Key by giving it a name, setting an optional expiration date, and clicking `Create API Key`. Copy the generated API Key for your records. The script will look for this as an environmental variable `UNIFI_API_KEY`.

  ### phpIPAM
  phpIPAM requires an API token to be created for a specific App. Think of it as a username/password for your scripts or other applications. Create an API key by logging into your phpIPAM interface as an Administrator and clicking `Administration > API`.  
  
  You'll then click `Create API key` and specify an App id (`IPAM_APP_ID`) and you should copy the generated App code for your records. The script will look for this as an environmental variable `IPAM_API_KEY`. Finally, change the App security option to `SSL with App code token`.

  ## To Do Items
  - ~~Create a dryrun switch in argparse~~
  - Log the changes instead of stdout only
  - Output is currently noisy. Try and reduce the amount of text generated, but keep the information provided

  ## Problems
  Please create a Github Issue and I will attempt to address the issues as time permits. This script is provided without warranty or promise and you should understand it makes **destructive** changes that are not recoverable.  

  ***Use at your own risk.***