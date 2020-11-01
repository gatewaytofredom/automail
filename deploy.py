import os
import socket
import platform
import sys
import argparse
import re

parser = argparse.ArgumentParser()

parser.add_argument(
    "--hostname",
    dest="hostname",
    type=str,
    default="auto",
    help="Sets the Hostname or FQDN to be used in configuration of the mail server.",
)

args = parser.parse_args()

# Check to make sure running on compatible operating system.
if "windows" in platform.system().lower():
    print("Automail is inteded to run on Ubuntu. \n Sorry!")
    sys.exit(1)

# Get system hostname.
if args.hostname == "auto":
    hostname = os.popen("hostname -f").read()
else:
    hostname = args.hostname

# Matches for a FQDN.
# Regex Explained here https://regex101.com/r/uXHuOZ/3
if re.search("^[^\.]+(\.[^\.]+)+$", hostname):
    print(f"FQDN detected as {hostname} \n")
else:
    print(f"Hostname detected as {hostname} \n")
    print(f"Please set a FQDN. \n")
    sys.exit(1)

# Set hostname in /etc/hostname

try:
    os.system(f" '{hostname}' > /etc/hostname  ")
except Exception as e:
    print(e)
    sys.exit(1)

# Update packages.
try:
    os.system("apt-get update -y")
except Exception as e:
    print(e)
    sys.exit(1)

# Preseed FQDN option for postfix install.
os.system(f'echo "postfix	postfix/mailname string {hostname}" | debconf-set-selections')

# Preseed Postfix to sending emails to other MTAs and receiving email from other MTAs.
os.system(
    "echo \"postfix postfix/main_mailer_type string 'Internet Site'\" | debconf-set-selections"
)

# Silent install postfix.
try:
    os.system("apt-get install -y postfix")
except Exception as e:
    print(e)
    sys.exit(1)
