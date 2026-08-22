import socket
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from relay.relay_server import (
    MAGIC,
    MAX_TOKEN,
    MSG_AUTH_OK,
    MSG_CLIENT_AUTH_TOKEN,
    MSG_HELLO,
    MSG_HELLO_OK,
    NONCE_LENGTH,
    CertificateBundle,
    HttpResponse,
    VERSION,
    RecordChannel,
    RelayError,
    bind_session,
    normalize_run_nonce,
    run_session,
)


class ChunkedSocket:
    def __init__(self, wire: bytes, chunk_size: int = 3):
        self.wire = bytearray(wire)
        self.chunk_size = chunk_size

    def recv(self, requested: int) -> bytes:
        count = min(requested, self.chunk_size, len(self.wire))
        if not count:
            return b""
        result = bytes(self.wire[:count])
        del self.wire[:count]
        return result


class ProtocolTests(unittest.TestCase):
    def record(self, kind: int, payload: bytes, version: int = VERSION) -> bytes:
        return struct.pack("!4sBBHI", MAGIC, version, kind, 0, len(payload)) + payload

    def test_fragmented_hello_is_reassembled(self):
        nonce = b"a" * NONCE_LENGTH
        channel = RecordChannel(ChunkedSocket(self.record(MSG_HELLO, nonce)))
        self.assertEqual(channel.receive({MSG_HELLO}), (MSG_HELLO, nonce))

    def test_wrong_version_is_rejected(self):
        channel = RecordChannel(ChunkedSocket(self.record(MSG_AUTH_OK, b"", version=1)))
        with self.assertRaisesRegex(RelayError, "invalid bridge header"):
            channel.receive({MSG_AUTH_OK})

    def test_wrong_direction_kind_is_rejected(self):
        wire = self.record(MSG_CLIENT_AUTH_TOKEN, b"token")
        channel = RecordChannel(ChunkedSocket(wire))
        with self.assertRaisesRegex(RelayError, "unexpected bridge message"):
            channel.receive({MSG_HELLO})

    def test_invalid_lengths_are_rejected_before_payload_read(self):
        short_hello = struct.pack("!4sBBHI", MAGIC, VERSION, MSG_HELLO, 0, NONCE_LENGTH - 1)
        with self.assertRaisesRegex(RelayError, "invalid bridge payload length"):
            RecordChannel(ChunkedSocket(short_hello)).receive({MSG_HELLO})
        oversized_token = struct.pack("!4sBBHI", MAGIC, VERSION, MSG_CLIENT_AUTH_TOKEN, 0, MAX_TOKEN + 1)
        with self.assertRaisesRegex(RelayError, "invalid bridge payload length"):
            RecordChannel(ChunkedSocket(oversized_token)).receive({MSG_CLIENT_AUTH_TOKEN})

    def test_nonce_normalization_and_validation(self):
        self.assertEqual(normalize_run_nonce("A" * 64), "a" * 64)
        self.assertEqual(len(normalize_run_nonce(None)), 64)
        with self.assertRaises(ValueError):
            normalize_run_nonce("a" * 63)
        with self.assertRaises(ValueError):
            normalize_run_nonce("g" * 64)

    def test_nonce_mismatch_never_acknowledges(self):
        left, right = socket.socketpair()
        try:
            right.sendall(self.record(MSG_HELLO, b"b" * NONCE_LENGTH))
            channel = RecordChannel(left)
            with self.assertRaisesRegex(RelayError, "does not match"):
                bind_session(channel, "a" * NONCE_LENGTH)
            right.settimeout(0.05)
            with self.assertRaises(TimeoutError):
                right.recv(1)
        finally:
            left.close()
            right.close()

    def test_matching_nonce_is_acknowledged(self):
        left, right = socket.socketpair()
        try:
            nonce = "c" * NONCE_LENGTH
            right.sendall(self.record(MSG_HELLO, nonce.encode("ascii")))
            bind_session(RecordChannel(left), nonce)
            header = right.recv(12)
            self.assertEqual(struct.unpack("!4sBBHI", header), (MAGIC, VERSION, MSG_HELLO_OK, 0, 0))
        finally:
            left.close()
            right.close()

    def test_auth_ok_releases_bof_before_python_enrollment(self):
        class FakeChannel:
            def __init__(self):
                self.sent = []
                self.terminal = False

            def receive(self, allowed):
                return MSG_CLIENT_AUTH_TOKEN, b"client-token"

            def send(self, kind, payload=b""):
                self.sent.append((kind, payload))

        class FakeHttp:
            def __init__(self, *args):
                self.responses = [
                    HttpResponse(401, {"www-authenticate": ["Negotiate"]}, b""),
                    HttpResponse(200, {}, b""),
                ]
                self.closed = False

            def request(self, *args, **kwargs):
                return self.responses.pop(0)

            def close(self):
                self.closed = True

        options = SimpleNamespace(
            verbose=False,
            machine="WIN11-01",
            adcs_host="ADCS.vmp.lab",
            adcs_address="10.6.10.12",
            adcs_port=80,
            auth_path="/certsrv/",
            trace_spnego=False,
            domain="vmp.lab",
            template="Machine",
            enroll_path="/certsrv/certfnsh.asp",
            certificate_path="/certsrv/certnew.cer",
        )
        channel = FakeChannel()
        bundle = CertificateBundle(certificate=object(), private_key=object(), request_id="test")
        with mock.patch("relay.relay_server.RawHttpConnection", FakeHttp), mock.patch(
            "relay.relay_server.enroll", return_value=bundle
        ) as enroll_mock:
            self.assertIs(run_session(channel, options), bundle)
        self.assertEqual(channel.sent, [(MSG_AUTH_OK, b"")])
        self.assertTrue(channel.terminal)
        enroll_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
