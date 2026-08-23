import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from relay.relay_server import (
    MAGIC,
    MAX_TOKEN,
    MSG_AUTH_OK,
    MSG_CLIENT_AUTH_TOKEN,
    CertificateBundle,
    HttpResponse,
    VERSION,
    RecordChannel,
    RelayError,
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

    def test_fragmented_token_is_reassembled(self):
        channel = RecordChannel(ChunkedSocket(self.record(MSG_CLIENT_AUTH_TOKEN, b"client-token")))
        self.assertEqual(channel.receive({MSG_CLIENT_AUTH_TOKEN}), (MSG_CLIENT_AUTH_TOKEN, b"client-token"))

    def test_wrong_version_is_rejected(self):
        channel = RecordChannel(ChunkedSocket(self.record(MSG_AUTH_OK, b"", version=1)))
        with self.assertRaisesRegex(RelayError, "invalid bridge header"):
            channel.receive({MSG_AUTH_OK})

    def test_wrong_direction_kind_is_rejected(self):
        wire = self.record(MSG_CLIENT_AUTH_TOKEN, b"token")
        channel = RecordChannel(ChunkedSocket(wire))
        with self.assertRaisesRegex(RelayError, "unexpected bridge message"):
            channel.receive({MSG_AUTH_OK})

    def test_invalid_lengths_are_rejected_before_payload_read(self):
        empty_token = struct.pack("!4sBBHI", MAGIC, VERSION, MSG_CLIENT_AUTH_TOKEN, 0, 0)
        with self.assertRaisesRegex(RelayError, "invalid bridge payload length"):
            RecordChannel(ChunkedSocket(empty_token)).receive({MSG_CLIENT_AUTH_TOKEN})
        oversized_token = struct.pack("!4sBBHI", MAGIC, VERSION, MSG_CLIENT_AUTH_TOKEN, 0, MAX_TOKEN + 1)
        with self.assertRaisesRegex(RelayError, "invalid bridge payload length"):
            RecordChannel(ChunkedSocket(oversized_token)).receive({MSG_CLIENT_AUTH_TOKEN})

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
        self.assertTrue(channel.bof_released)
        enroll_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
