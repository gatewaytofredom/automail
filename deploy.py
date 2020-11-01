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

parser.add_argument(
    "--postmaster",
    dest="postmaster",
    type=str,
    default="root",
    help="Sets an ailias for the Postmaster required by RFC 2142. This can be any user on the system.",
)

parser.add_argument(
    "--webserver",
    dest="webserverType",
    type=str,
    default="none",
    choices=["apache", "nginx"],
    help="Sets the webserver(Apache or Nginx) to use when generating TLS certificates with Certbot.",
)

parser.add_argument(
    "--certbotEmail",
    dest="certbotEmail",
    type=str,
    default="postmaster",
    help="Sets the email account to associate with Certbot. This is where emails realated to your TLS certificate will be sent.",
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

# Edit hostname.
mainCf = open("/etc/postfix/main.cf").read().splitlines()
mainCf[37] = f"myhostname = {hostname}"
open("/etc/postfix/main.cf", "w").write("\n".join(mainCf))

os.system("systemctl restart postfix")

# Edit postmaster alias.
aliasesFile = open("/etc/aliases").read().splitlines()

for line in aliasesFile:
    if line.startswith("postmaster"):
        line = f"postmaster :{args.postmaster}"
open("/etc/aliases", "w").write("\n".join(mainCf))

# Open ports for postfix MTA, Dovecot IMAP server, and apache server
os.system("ufw allow 25,80,443,587,465,143,993/tcp")

try:
    os.system("apt install certbot")
except Exception as e:
    print(e)
    sys.exit(1)

# Install TLS certificate using certbot and corresponding apache2 plugin.
if args.webserver.lower() == "apache":
    try:
        os.system("apt install python3-certbot-apache")

        # Create the virtual host file.
        virtualHostFile = open(
            f"/etc/apache2/sites-available/{hostname}.conf", "w"
        ).write(
            f"""<VirtualHost *:80>\n
            \tServerName {hostname}\n
            \tDocumentRoot /var/www/{hostname}\n
            </VirtualHost>"""
        )

        # Create web root directory.
        os.system(f"mkdir /var/www/{hostname}")

        # Set www-data (Apache user) as the owner of the web root.
        os.system(f"chown www-data:www-data /var/www/{hostname} -R")

        # Enable the virtual host configuration.
        os.system(f"a2ensite {hostname}.conf")

        # Reload Apache to put changes into effect.
        os.system("systemctl reload apache2")

        # Run certbot and obtain Let's Encrypt TLS certificate.
        if args.certbotEmail == "postmaster":

            os.system(
                f"certbot --apache --agree-tos --redirect --hsts --staple-ocsp --email postmaster@{hostname} -d {hostname}"
            )
        else:
            os.system(
                f"certbot --apache --agree-tos --redirect --hsts --staple-ocsp --email {args.certbotEmail} -d {hostname}"
            )

    except Exception as e:
        print(e)
        sys.exit(1)

else:
    try:
        os.system("apt install python3-certbot-nginx ")

        # Create the virtual host file.
        virtualHostFile = open(f"/etc/nginx/conf.d/{hostname}.conf", "w").write(
            f"""server {{\n
            \tlisten 80;\n
            \tlisten [::]:80;\n
            \tserver_name mail.your-domain.com;\n\n
            \troot /var/www/mail.your-domain.com/;\n\n
            \tlocation ~ /.well-known/acme-challenge {{\n
            \tallow all;\n
        \t}}\n
            }}"""
        )

        # Create web root directory.
        os.system(f"mkdir /var/www/{hostname} ")

        # Set www-data (Nginx user) as the owner of the web root.
        os.system(f"chown www-data:www-data /var/www/{hostname} -R")

        # Reload Nginx to put changes into effect.
        os.system("systemctl reload nginx")

        # Run certbot and obtain Let's Encrypt TLS certificate.
        if args.certbotEmail == "postmaster":

            os.system(
                f"certbot --nginx --agree-tos --redirect --hsts --staple-ocsp --email postmaster@{hostname} -d {hostname}"
            )
        else:
            os.system(
                f"certbot --nginx --agree-tos --redirect --hsts --staple-ocsp --email {args.certbotEmail} -d {hostname}"
            )

    except Exception as e:
        print(e)
        sys.exit(1)