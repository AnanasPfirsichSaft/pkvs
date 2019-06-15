# pkvs

## Description

pkvs is the "PHP Key Vault Server" and is meant to provide keys for
en- and decryption over a network. This can be a direct connection or
for example through an encrypted (ssh) tunnel. Client authentication
is optional in trusted environments.

Multiple users ("key group") are supported. Each have their passphrase
and allowed keys to fetch. Configuration can be done directly or by
xml formatted data. pkvs has security in mind but cannot do very much
as the PHP interpreter is in control. "Super safe" installations will
require additional steps.

## Requirements

* [PHP](http://www.php.net/). Versions less than 7.x are untested.

* The following extensions: sockets and openssl.

## Audience

People who want to run a (shared) protected vault to have keys ready. For
example to encrypt (external) disks or login to networks or websites. It is
explicitly not a desktop password manager. And obviously it lacks hardware
protection like a token or smartcard. You need basic knowlegde to command
line interfaces to get it run.

## Install

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

## Updates

Well, overwrite existing files (after backup) with the new one.

## Uninstall

Remove the systemd activation, if you have enabled it before: "systemctl disable pkvs".

Well, then delete any files?

## License

All files are released to the [MIT License](https://github.com/AnanasPfirsichSaft/pkvs/blob/master/LICENSE).
