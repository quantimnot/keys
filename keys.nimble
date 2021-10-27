version     = "0.1.0"
author      = "quantimnot"
description = "Generate ed25519 keys/certs for tor, ssh, pgp, x509 from a passphrase."
license     = "MIT"
srcDir      = "."
installExt  = @["nim"]
bin         = @["keys"]

requires "base32"
requires "yaml"
requires "cligen"
requires "nimcrypto"
