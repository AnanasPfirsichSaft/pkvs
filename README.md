# pkvs

## Description

pkvs is the "PHP Key Vault Server" and is meant to provide keys for
en– and decryption over a network. This can be a direct connection or
for example through an encrypted (ssh) tunnel. Client authentication
is optional in trusted environments.

Multiple users ("key group") are supported. Each have their passphrase
and allowed keys to fetch. Configuration can be done directly or by
xml formatted data. pkvs has security in mind but cannot do very much
as the PHP interpreter is in control. "Super safe" installations will
require additional steps. See below.

## Requirements

* [PHP](http://www.php.net/). Versions less than 7.x are untested.

* The following extensions: sockets (full version), shmop (lite version) and openssl.

## Audience

People who want to run a (shared) protected vault to have keys ready. For
example to encrypt (external) disks or login to networks or websites. It is
explicitly not a desktop password manager. And obviously it lacks hardware
protection like a token or smartcard. You need basic knowlegde to command
line interfaces to get it run.

## Install (Full)

The full version is a daemon handling its connections with sockets using
PHP functions directly. All data is kept in memory only.

_⚠ As of PHP 8 sockets seem to be broken. Use "lite version" instead.
Currently I am not fancy to fix it…_

_⚠ The default connection is unencrypted!_

Run the "server.php". It starts listening on your local network interface
on port 2019. You can change this at the first lines of the file. All keys
are encrypted with a session key (changing on every startup) where the second
half can origin from an external data source like a (static) keyfile.
In this case everytime you get a key the session key is compiled from both.
Afterwards it is cleared from memory. If the second half becomes inaccessible,
you will not be able to decrypt the vault anymore.

Use the "client.php" to fed the example "pkvs_data.xml" into the server. You
can have the "server.php" hash your own authentication passphrases and generate
keys to make your custom xml file. Eventually they do not have to be located on
the same machine.

The "proxy.php" can help to include a present webserver. You can secure it
with TLS and certificate pinning and forward the key request to the (local)
running pkvs.

"pkvs.service" is a systemd unit file. Copy it to "/etc/systemd/system" and
reload your daemon with "systemctl daemon-reload". Try to start pkvs with
"systemctl start pkvs". If it works, you can make it start every time your
machine boots, "systemctl enable pkvs".
You should store the "pkvs_data.xml" in a safe place. The PSK´s are hashed,
but the keys are plaintext. Unless you use another layer like HMAC them :)

## Examples

```
server.php --cipher=auto
server.php --hash-psk
server.php --gen-key=1,256
server.php --gen-key=0,128

client.php --host=localhost:2019 --file=pkvs_data.xml
client.php --host=localhost:2019 --file=pkvs_data.xml --auth=-

https://domain.example/proxy.php?key=1&auth=foobar
https://domain.example/proxy.php?key=2&auth=baz&addlog=i+will+be+seen+in+syslog

telnet localhost 2019
S: 100 [PKVS] [V1] [AUTH] Random greeting...
C: auth passphrase
S: 200 credentials confirmed, group id is [number]
C: get 1
S: [thekey]
C: quit
S: bye
```

## Install (Lite)

The lite version is supposed to be run from a PHP capable webserver.
You can stick to the internal development server of PHP. All data is
kept in memory only.

Copy the "lite.php" to a directory your webserver can access. Or a
new one, if you like to serve it by PHP’s internal webserver.

/usr/bin/php -S ip6-localhost:2022 -t /path/to/pkvs

_⚠ The default connection is unencrypted!_

For example with apache you can use this snippet to provide TLS as
a proxy.

```
<Location /pkvs>
ProxyPass "http://ip6-localhost:2022/lite.php"
</Location>
```

The lite version differs from the full version. Its cipher is hardcoded
to "aes-256-ctr" and the second half of the key must come from an external
file (called "pool"). The configuration is set by a XML file only. Authorization
keys ("PSK") should be created with the full version, "server.php --hash-psk".

After setting the configuration you can copy the long return string as "integrity"
to your XML file. This makes sure that your data was imported correctly.

"pkvs-lite.service" is a systemd unit file. Copy it to "/etc/systemd/system" and
reload your daemon with "systemctl daemon-reload". Try to start pkvs with
"systemctl start pkvs-lite". If it works, you can make it start every time your
machine boots, "systemctl enable pkvs-lite".

## Examples

```
Proxied URI:
wget --content-on-error -O - 'https://domain.example/pkvs/?cmd='

Normal URI:
wget --content-on-error -O - --post-file ./pkvs_data_lite.xml 'http://ip6-localhost:2022/lite.php?cmd=init'
wget --content-on-error -O - 'http://ip6-localhost:2022/lite.php?cmd=lock'
wget --content-on-error -O - 'http://ip6-localhost:2022/lite.php?cmd=get&key=1&auth=deckard'
wget --content-on-error -O - 'http://ip6-localhost:2022/lite.php?cmd=get&key=1&auth=deckard'
wget --content-on-error -O - 'http://ip6-localhost:2022/lite.php?cmd=shutdown&auth=adria'

Pinning the TLS cert of your proxy:
openssl s_client -connect domain.example:443 | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
wget --pinnedpubkey='[String with letters, digits and equal sign]' --content-on-error […]
```

## Updates

Well, overwrite existing files (after backup) with the new one.

## Uninstall

Remove the systemd activation, if you have enabled it before: "systemctl disable pkvs(-lite)".

Well, then delete any files?

## "Super Safe"

I try to sanitize every sensitive data after usage. All data is to remain in memory only.
Please consider this when you have configured an unencrypted(!) swap. You can split the session
key in half and have the "right" side come from an external file source. If it gets unavailable,
keys from the vault can no longer be decrypted. But it can be make available again. Imagine
a usb stick as a simple dongle.

But to be honest, I don’t know how exactly memory is managed by PHP and the OS. Hope it is
enough… 😉

## License

All files are released to the [MIT License](https://github.com/AnanasPfirsichSaft/pkvs/blob/master/LICENSE).
