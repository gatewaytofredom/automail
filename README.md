# AutoMail
Automatic configurable mail server deployment script.

Deploys a [Postfix](http://www.postfix.org/) Mail Transfer Agent and a [Dovecot](https://www.dovecot.org/) IMAP server.  
Optionaly generates SSL certificates using [Certbot](https://certbot.eff.org/)

## Configuration Flags

#### --hostname
Sets the Hostname or FQDN to be used in configuration of the mail server.

If the hostname flag is not set the system hostname will be used if it's a FQDN.

#### --postmaster
Sets an ailias for the Postmaster required by RFC 2142. This can be any user on the system.

Defaults to setting the root user as the system postmaster.

#### --webserver
Sets the webserver(Apache or Nginx) to use when generating TLS certificates with Certbot.

Defaults to none if a webserver isn't set.

#### --certbotEmail
Sets the email account to associate with Certbot. This is where emails realated to your TLS certificate will be sent.

Defaults to the system postmaster.

#### --skipSSL
Skips Certbot's SSL certificate generation. Use this flag if you plan on using your own certificates.

Defualts to False.


## Usage

Run deploy.py as root using python 3.5+.

`python
sudo deploy.py --hostname robertowens.dev --webserver Apache
`

## License
[Unlicense](https://choosealicense.com/licenses/unlicense/)
