import os
import socket
import platform
import sys
import argparse
import re
from textwrap import dedent

parser = argparse.ArgumentParser()

parser.add_argument(
    "--hostname",
    dest="hostname",
    type=str,
    default="auto",
    help="Sets the Hostname or FQDN to be used in configuration of the mail server.",
)

# TODO: get current user for default.
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

parser.add_argument(
    "--skipSSL",
    dest="skipSSL",
    type=bool,
    default="false",
    help="Skips Certbot's SSL certificate generation.",
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
    os.system("apt install certbot -y")
except Exception as e:
    print(e)
    sys.exit(1)

# Install TLS certificate using certbot and corresponding apache2 plugin.
if args.webserverType.lower() == "apache":
    try:
        os.system("apt install python3-certbot-apache -y")

        # Create the virtual host file.
        virtualHostFile = open(
            f"/etc/apache2/sites-available/{hostname}.conf", "w"
        ).write(
            dedent(
                f"""<VirtualHost *:80>\n
            \tServerName {hostname}\n
            \tDocumentRoot /var/www/{hostname}\n
            </VirtualHost>"""
            )
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
        os.system("apt install python3-certbot-nginx -y ")

        # Create the virtual host file.
        virtualHostFile = open(f"/etc/nginx/conf.d/{hostname}.conf", "w").write(
            dedent(
                f"""server {{\n
            \tlisten 80;\n
            \tlisten [::]:80;\n
            \tserver_name {hostname};\n\n
            \troot /var/www/{hostname}/;\n\n
            \tlocation ~ /.well-known/acme-challenge {{\n
            \tallow all;\n
        \t}}\n
            }}"""
            )
        )

        # Create web root directory.
        os.system(f"mkdir /var/www/{hostname} ")

        # Set www-data (Nginx user) as the owner of the web root.
        os.system(f"chown www-data:www-data /var/www/{hostname} -R")

        # Reload Nginx to put changes into effect.
        os.system("systemctl reload nginx")

        # Run certbot and obtain Let's Encrypt TLS certificate.

        if args.skipSSL == "false":

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

# Enable Submission Service in Postfix.

masterCf = open("/etc/postfix/master.cf", "a").write(
    dedent(
        """submission     inet     n    -    y    -    -    smtpd
 \t-o syslog_name=postfix/submission
 \t-o smtpd_tls_security_level=encrypt
 \t-o smtpd_tls_wrappermode=no
 \t-o smtpd_sasl_auth_enable=yes
 \t-o smtpd_relay_restrictions=permit_sasl_authenticated,reject
 \t-o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
 \t-o smtpd_sasl_type=dovecot
 \t-o smtpd_sasl_path=private/auth"""
    )
)


# TODO: enable submission service on port 465 for Microsoft Outlook mail clients.

# Specify location of TLS certificate and private key for Postfix.
mainCf = open("/etc/postfix/main.cf").read().splitlines()
mainCf[28] = f"smtpd_tls_cert_file=/etc/letsencrypt/live/{hostname}/fullchain.pem"
mainCf[29] = f"smtpd_tls_cert_file=/etc/letsencrypt/live/{hostname}/privkey.pem"
open("/etc/postfix/main.cf", "w").write("\n".join(mainCf))

os.system("systemctl restart postfix")

try:
    os.system("apt install dovecot-pop3d -y")
except Exception as e:
    print(e)
    sys.exit(1)

# Enable IMAP protocol for Dovecot.
dovecotConf = open("/etc/dovecot/dovecot.conf", "a").write("protocols = imap\n")

# Set Dovecot to use Maildir format to store email messages.
mailboxConf = open("/etc/dovecot/conf.d/10-mail.conf").read().splitlines()
mailboxConf[30] = f"mail_location = mbox:~/mail:INBOX=/var/mail/%u"
open("/etc/postfix/main.cf", "w").write("\n".join(mailboxConf))

# TODO: Merge multiple openings of /etc/dovecot/conf.d/10-auth.conf into one.

# Configure authentication mechanism.
mailAuthConf = open("/etc/dovecot/conf.d/10-auth.conf").read().splitlines()
for index, line in enumerate(mailAuthConf):
    if "disable_plaintext_auth" in line:
        mailAuthConf[index] = "disable_plaintext_auth = yes"
open("/etc/dovecot/conf.d/10-auth.conf", "w").write("\n".join(mailAuthConf))

mailAuthConf = open("/etc/dovecot/conf.d/10-auth.conf", "a").write(
    "auth_username_format = %n\nauth_mechanisms = plain login"
)
# Configure SSL/TLS Encryption.
SSLConf = open("/etc/dovecot/conf.d/10-ssl.conf").read().splitlines()
for index, line in enumerate(SSLConf):
    if "ssl = yes" in line:
        SSLConf[index] = "ssl = required"
    if "ssl_cert =" in line:
        SSLConf[index] = f"ssl_cert = </etc/letsencrypt/live/{hostname}/fullchain.pem"
    if "ssl_key =" in line:
        SSLConf[index] = f"ssl_key = </etc/letsencrypt/live/{hostname}/privkey.pem"
    if "ssl_prefer_server_ciphers =" in line:
        SSLConf[index] = f"ssl_prefer_server_ciphers = yes"
    if "ssl_min_protocol =" in line:
        SSLConf[index] = f"ssl_min_protocol = TLSv1.2"
open("/etc/dovecot/conf.d/10-ssl.conf", "w").write("\n".join(SSLConf))

# Configure Authentication between Postfix and Dovecot.
masterConf = open("/etc/dovecot/conf.d/10-master.conf").read().splitlines()
for index, line in enumerate(masterConf):
    if "unix_listener auth-userdb" in line:
        masterConf[index] = "unix_listener /var/spool/postfix/private/auth {"
    if (
        "mode = 0666" in line
        and masterConf[index - 1] == "unix_listener /var/spool/postfix/private/auth {"
    ):
        masterConf[index] = "mode = 0660"
    if (
        "#user = " in line
        and masterConf[index - 2] == "unix_listener /var/spool/postfix/private/auth {"
    ):
        masterConf[index] = "user = postfix"
    if (
        "#group =" in line
        and masterConf[index - 3] == "unix_listener /var/spool/postfix/private/auth {"
    ):
        masterConf[index] = "group = postfix\n"
open("/etc/dovecot/conf.d/10-master.conf", "w").write("\n".join(masterConf))

# Setup auto creation of Sent and Trash folders

# TODO: Create args/flags for specifying what mailboxes a user wants to create.

mailboxesConf = open("/etc/dovecot/conf.d/15-mailboxes.conf").read().splitlines()
for index, line in enumerate(mailboxesConf):
    if "mailbox Trash {" in line:
        mailboxesConf[index] = "mailbox Trash {\nauto = create"
    if "mailbox Draft {" in line:
        mailboxesConf[index] = "mailbox Draft {\nauto = create"
    if "mailbox Junk {" in line:
        mailboxesConf[index] = "mailbox Junk {\nauto = create"
    if "mailbox Sent {" in line:
        mailboxesConf[index] = "mailbox Sent {\nauto = create"
open("/etc/dovecot/conf.d/15-mailboxes.conf", "w").write("\n".join(mailboxesConf))

# Restart Postfix & Dovecot to enable new configuration changes.
try:
    os.system("systemctl restart dovecot")
    os.system("systemctl restart postfix")
except Exception as e:
    print(e)
    sys.exit(1)

try:
    os.system("apt install dovecot-lmtpd -y")
except Exception as e:
    print(e)
    sys.exit(1)

dovecotConf = open("/etc/dovecot/dovecot.conf", "a").write("protocols = imap lmtp")

# Set Dovecot to deliver email to message store.
masterConf = open("/etc/dovecot/conf.d/10-master.conf").read().splitlines()
for index, line in enumerate(masterConf):
    if "unix_listener lmtp" in line:
        masterConf[index] = "unix_listener /var/spool/postfix/private/dovecot-lmtp {"
    if "#mode = 0666" in line and "dovecot-lmtp" in masterConf[index - 1]:
        masterConf[index] = "mode = 0600\nuser = postfix\ngroup = postfix\n"
open("/etc/dovecot/conf.d/10-master.conf", "w").write("\n".join(masterConf))

dovecotConf = open("/etc/postfix/main.cf", "a").write(
    "mailbox_transport = lmtp:unix:private/dovecot-lmtp\nsmtputf8_enable = no"
)

# Restart Postfix and Dovecot to enable config changes.

try:
    os.system("systemctl restart postfix dovecot")
except Exception as e:
    print(e)
    sys.exit(1)
