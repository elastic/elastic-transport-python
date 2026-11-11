#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

import base64
import hashlib
import http.server
import socket
import ssl
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Type

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from elastic_transport import (
    AiohttpHttpNode,
    ConnectionError,
    ConnectionTimeout,
    NodeConfig,
    RequestsHttpNode,
    TlsError,
    Urllib3HttpNode,
)
from elastic_transport._node._base import BaseNode


def _material() -> Tuple[bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
    now = datetime.now(timezone.utc)
    ca_key = _key()
    ca_name = _cn("Test Dev CA")
    ca_cert = _cert(
        ca_name,
        ca_name,
        ca_key,
        ca_key,
        now - timedelta(days=1),
        now + timedelta(days=2),
        ca=True,
    )
    good_key = _key()
    forged_key = _key()
    expired_key = _key()
    other_key = _key()
    return (
        _pem_cert(ca_cert),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                good_key,
                ca_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="localhost",
            )
        ),
        _pem_key(good_key),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                forged_key,
                forged_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="localhost",
            )
        ),
        _pem_key(forged_key),
        _pem_cert(
            _cert(
                _cn("localhost"),
                ca_name,
                expired_key,
                ca_key,
                now - timedelta(days=10),
                now - timedelta(days=1),
                san="localhost",
            )
        ),
        _pem_key(expired_key),
        _pem_cert(
            _cert(
                _cn("other.example"),
                ca_name,
                other_key,
                ca_key,
                now - timedelta(days=1),
                now + timedelta(days=2),
                san="other.example",
            )
        ),
        _pem_key(other_key),
    )


def _key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cn(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _cert(
    subject: x509.Name,
    issuer: x509.Name,
    key: RSAPrivateKey,
    signer: RSAPrivateKey,
    start: datetime,
    end: datetime,
    ca: bool = False,
    san: str = "",
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(True, None), critical=True
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(signer, hashes.SHA256())


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


CA_PEM, GOOD, GOOD_KEY, FORGED, FORGED_KEY, EXPIRED, EXPIRED_KEY, OTHER, OTHER_KEY = (
    _material()
)
FINGERPRINT = hashlib.sha256(ssl.PEM_cert_to_DER_cert(CA_PEM.decode())).hexdigest()
LEAF_FINGERPRINT = hashlib.sha256(ssl.PEM_cert_to_DER_cert(GOOD.decode())).hexdigest()
COLON_FINGERPRINT = ":".join(
    FINGERPRINT[i : i + 2] for i in range(0, len(FINGERPRINT), 2)
).upper()

NODES = [Urllib3HttpNode, RequestsHttpNode]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: "_Server" = self.server  # type: ignore[assignment]
        server.hits += 1
        auth = self.headers.get("Authorization")
        if auth is not None:
            server.auths.append(auth)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _Server(http.server.HTTPServer):
    hits: int
    auths: list
    names: List[Optional[str]]

    def __init__(self, address: Tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, _Handler)
        self.hits = 0
        self.auths = []
        self.names = []
        self.socket = context.wrap_socket(self.socket, server_side=True)


@contextmanager
def serve(leaf: bytes, key: bytes, require_client: bool = False) -> Iterator[_Server]:
    with tempfile.TemporaryDirectory() as tmp:
        chain = Path(tmp) / "chain.pem"
        key_path = Path(tmp) / "key.pem"
        chain.write_bytes(leaf + b"\n" + CA_PEM)
        key_path.write_bytes(key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(chain), keyfile=str(key_path))
        names: List[Optional[str]] = []

        def _sni(
            _sock: ssl.SSLObject, server_name: Optional[str], _ctx: ssl.SSLContext
        ) -> None:
            names.append(server_name)

        context.sni_callback = _sni
        if require_client:
            context.load_verify_locations(cadata=CA_PEM.decode())
            context.verify_mode = ssl.CERT_REQUIRED
        server = _Server(("127.0.0.1", 0), context)
        server.names = names
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()


class _Proxy:
    def __init__(self, target_port: int, user: str, password: str) -> None:
        self.target_port = target_port
        self.expected = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        self.connects = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._sock.close()

    def _accept(self) -> None:
        while True:
            try:
                client, _addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
            header, rest = data.split(b"\r\n\r\n", 1)
            if f"Proxy-Authorization: Basic {self.expected}".encode() not in header:
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return
            self.connects += 1
            upstream = socket.create_connection(("127.0.0.1", self.target_port))
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            left = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
            right = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
            left.start()
            right.start()
        except OSError:
            client.close()


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(8192)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        return
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            return


def _port(server: _Server) -> int:
    port = server.server_address[1]
    assert isinstance(port, int)
    return port


def _pinned_context(node: BaseNode) -> ssl.SSLContext:
    if isinstance(node, Urllib3HttpNode):
        assert node.pool is not None
        context = node.pool.conn_kw["ssl_context"]
        assert node.pool.ca_certs is None
    else:
        context = node._adapter._pinned_context  # type: ignore[attr-defined]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) == 1
    return context


@pytest.mark.parametrize("node_cls", NODES)
def test_constructor_does_not_connect(node_cls: Type[BaseNode]) -> None:
    node = node_cls(
        NodeConfig(
            "https",
            "127.0.0.1",
            1,
            ssl_assert_fingerprint="ab" * 32,
        )
    )
    if isinstance(node, Urllib3HttpNode):
        assert node.pool is None
    node.close()


@pytest.mark.parametrize("node_cls", NODES)
@pytest.mark.parametrize("fingerprint", ["", "../", "?#", "/etc/passwd", "FO:OB:AR"])
def test_bad_fingerprint_sends_no_http(
    node_cls: Type[BaseNode], fingerprint: str
) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        with pytest.raises(ValueError):
            node_cls(
                NodeConfig(
                    "https",
                    "localhost",
                    _port(server),
                    ssl_assert_fingerprint=fingerprint,
                )
            )
        assert server.hits == 0


@pytest.mark.parametrize("node_cls", [*NODES, AiohttpHttpNode])
@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ({"verify_certs": False}, "verify_certs"),
        ({"ca_certs": "../"}, "ca_certs"),
        ({"ssl_context": ssl.create_default_context()}, "ssl_context"),
    ],
)
def test_rejects_other_trust_settings(
    node_cls: Type[BaseNode], extra: dict, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        node_cls(
            NodeConfig(
                "https",
                "localhost",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                **extra,
            )
        )


@pytest.mark.parametrize("node_cls", NODES)
def test_probe_presents_the_client_cert(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY, require_client=True) as server:
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp) / "client.pem"
            key = Path(tmp) / "client.key"
            cert.write_bytes(GOOD)
            key.write_bytes(GOOD_KEY)
            node = node_cls(
                NodeConfig(
                    "https",
                    "localhost",
                    _port(server),
                    ssl_assert_fingerprint=FINGERPRINT,
                    client_cert=str(cert),
                    client_key=str(key),
                )
            )
            try:
                meta, _body = node.perform_request("GET", "/")
                assert meta.status == 200
                assert server.hits == 1
            finally:
                node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_probe_uses_assert_hostname_for_sni(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "127.0.0.1",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname="localhost",
            )
        )
        try:
            meta, _body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.names[0] == "localhost"
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_request_uses_assert_hostname_for_sni(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "127.0.0.1",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname="localhost",
            )
        )
        try:
            node.perform_request("GET", "/")
            assert server.names == ["localhost", "localhost"]
        finally:
            node.close()


def test_urllib3_probe_ignores_env_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")
    with serve(GOOD, GOOD_KEY) as server:
        node = Urllib3HttpNode(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
            )
        )
        try:
            meta, _body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.hits == 1
        finally:
            node.close()


def test_requests_probe_uses_the_session_proxy() -> None:
    with serve(GOOD, GOOD_KEY) as server:
        proxy = _Proxy(_port(server), "a", "p@ss")
        node = RequestsHttpNode(
            NodeConfig(
                "https",
                "127.0.0.1",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname="localhost",
            )
        )
        node.session.trust_env = False  # type: ignore[attr-defined]
        node.session.proxies["https"] = f"http://a:p%40ss@127.0.0.1:{proxy.port}"  # type: ignore[attr-defined]
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert proxy.connects >= 2
        finally:
            node.close()
            proxy.close()


def test_requests_probe_uses_a_host_specific_proxy() -> None:
    with serve(GOOD, GOOD_KEY) as server:
        proxy = _Proxy(_port(server), "a", "p")
        node = RequestsHttpNode(
            NodeConfig(
                "https",
                "127.0.0.1",
                1,
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname="localhost",
            )
        )
        node.session.trust_env = False  # type: ignore[attr-defined]
        node.session.proxies["https://127.0.0.1"] = f"http://a:p@127.0.0.1:{proxy.port}"  # type: ignore[attr-defined]
        try:
            meta, _body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.hits == 1
            assert proxy.connects >= 2
        finally:
            node.close()
            proxy.close()


def test_requests_probe_rejects_https_proxy() -> None:
    node = RequestsHttpNode(
        NodeConfig("https", "127.0.0.1", 1, ssl_assert_fingerprint=FINGERPRINT)
    )
    node.session.trust_env = False  # type: ignore[attr-defined]
    node.session.proxies["https"] = "https://127.0.0.1:1"  # type: ignore[attr-defined]
    try:
        with pytest.raises(TlsError, match="https:// proxy"):
            node.perform_request("GET", "/")
    finally:
        node.close()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    assert isinstance(port, int)
    return port


@pytest.mark.parametrize("node_cls", NODES)
def test_probe_connection_failure_is_a_connection_error(
    node_cls: Type[BaseNode],
) -> None:
    node = node_cls(
        NodeConfig(
            "https", "127.0.0.1", _closed_port(), ssl_assert_fingerprint=FINGERPRINT
        )
    )
    try:
        with pytest.raises(ConnectionError):
            node.perform_request("GET", "/")
    finally:
        node.close()


@contextmanager
def silent_server() -> Iterator[int]:
    """Accepts TCP but never answers the TLS handshake."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        yield sock.getsockname()[1]


@pytest.mark.parametrize("node_cls", NODES)
def test_probe_timeout_is_a_connection_timeout(node_cls: Type[BaseNode]) -> None:
    with silent_server() as port:
        node = node_cls(
            NodeConfig(
                "https",
                "127.0.0.1",
                port,
                ssl_assert_fingerprint=FINGERPRINT,
                request_timeout=0.2,
            )
        )
        try:
            with pytest.raises(ConnectionTimeout):
                node.perform_request("GET", "/")
        finally:
            node.close()


@pytest.mark.asyncio
async def test_aiohttp_probe_timeout_is_a_connection_timeout() -> None:
    with silent_server() as port:
        node = AiohttpHttpNode(
            NodeConfig(
                "https",
                "127.0.0.1",
                port,
                ssl_assert_fingerprint=FINGERPRINT,
                request_timeout=0.2,
            )
        )
        try:
            with pytest.raises(ConnectionTimeout):
                await node.perform_request("GET", "/")
        finally:
            await node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_probe_uses_the_request_timeout(node_cls: Type[BaseNode]) -> None:
    with silent_server() as port:
        node = node_cls(
            NodeConfig(
                "https",
                "127.0.0.1",
                port,
                ssl_assert_fingerprint=FINGERPRINT,
                request_timeout=3,
            )
        )
        try:
            start = time.monotonic()
            with pytest.raises(ConnectionTimeout):
                node.perform_request("GET", "/", request_timeout=0.2)
            assert time.monotonic() - start < 2
        finally:
            node.close()


@pytest.mark.asyncio
async def test_aiohttp_probe_uses_the_request_timeout() -> None:
    with silent_server() as port:
        node = AiohttpHttpNode(
            NodeConfig(
                "https",
                "127.0.0.1",
                port,
                ssl_assert_fingerprint=FINGERPRINT,
                request_timeout=3,
            )
        )
        try:
            start = time.monotonic()
            with pytest.raises(ConnectionTimeout):
                await node.perform_request("GET", "/", request_timeout=0.2)
            assert time.monotonic() - start < 2
        finally:
            await node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_pin_sends_one_request(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=COLON_FINGERPRINT,
                headers={"authorization": "ApiKey secret"},
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert server.auths == ["ApiKey secret"]
            context = _pinned_context(node)
            assert context.check_hostname is False
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.hits == 2
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_leaf_fingerprint_is_a_trust_anchor(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=LEAF_FINGERPRINT,
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            # get_ca_certs skips non-CA trust anchors, so a leaf pin stays an empty list
            context = (
                node.pool.conn_kw["ssl_context"]
                if isinstance(node, Urllib3HttpNode)
                else node._adapter._pinned_context  # type: ignore[attr-defined]
            )
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.get_ca_certs() == []
        finally:
            node.close()


def test_requests_session_fails_closed_before_pin() -> None:
    import requests

    with serve(GOOD, GOOD_KEY) as server:
        node = RequestsHttpNode(
            NodeConfig(
                "https", "localhost", _port(server), ssl_assert_fingerprint=FINGERPRINT
            )
        )
        try:
            request = node.session.prepare_request(
                requests.Request("GET", node.base_url)
            )
            with pytest.raises(TlsError, match="not pinned"):
                node.session.send(request, verify=False)
            assert server.hits == 0
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_forged_leaf_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(FORGED, FORGED_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                headers={"authorization": "ApiKey secret"},
            )
        )
        try:
            with pytest.raises(TlsError, match="signature|certificate|verify") as exc:
                node.perform_request("GET", "/")
            assert "Fingerprints did not match" not in str(exc.value)
            assert server.hits == 0
            assert server.auths == []
            _pinned_context(node)
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_expired_certificate_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(EXPIRED, EXPIRED_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
            )
        )
        try:
            with pytest.raises(TlsError, match="expired"):
                node.perform_request("GET", "/")
            assert server.hits == 0
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_hostname_mismatch_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(OTHER, OTHER_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname=True,
            )
        )
        try:
            with pytest.raises(TlsError, match="Hostname mismatch") as exc:
                node.perform_request("GET", "/")
            assert "Fingerprints did not match" not in str(exc.value)
            assert server.hits == 0
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_hostname_off_by_default(node_cls: Type[BaseNode]) -> None:
    with serve(OTHER, OTHER_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_hostname_opt_out(node_cls: Type[BaseNode]) -> None:
    with serve(OTHER, OTHER_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint=FINGERPRINT,
                ssl_assert_hostname=False,
            )
        )
        try:
            meta, body = node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert _pinned_context(node).check_hostname is False
        finally:
            node.close()


@pytest.mark.parametrize("node_cls", NODES)
def test_wrong_fingerprint_sends_no_request(node_cls: Type[BaseNode]) -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = node_cls(
            NodeConfig(
                "https",
                "localhost",
                _port(server),
                ssl_assert_fingerprint="0" * 64,
            )
        )
        try:
            with pytest.raises(TlsError, match="Fingerprints did not match") as exc:
                node.perform_request("GET", "/")
            assert "0" * 64 in str(exc.value)
            assert server.hits == 0
        finally:
            node.close()


def test_leaf_only_fallback_names_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    from elastic_transport._node import _ca_fingerprint as ca

    monkeypatch.setattr(
        ca, "_peer_ders", lambda config, timeout, proxy: ([b"\x00"], True)
    )
    with pytest.raises(TlsError, match="Only the leaf certificate was available"):
        ca._matching_certificate_pem(
            NodeConfig("https", "localhost", 1, ssl_assert_fingerprint="ab" * 32),
            None,
            None,
        )


def _aiohttp_node(port: int, **kwargs: object) -> AiohttpHttpNode:
    return AiohttpHttpNode(
        NodeConfig(
            "https",
            "127.0.0.1",
            port,
            headers={"authorization": "ApiKey secret"},
            **kwargs,  # type: ignore[arg-type]
        )
    )


@pytest.mark.asyncio
async def test_aiohttp_https_session_needs_a_context() -> None:
    node = _aiohttp_node(1, ssl_assert_fingerprint=FINGERPRINT)
    # Never fall back to ssl=False for https.
    with pytest.raises(AssertionError):
        node._create_aiohttp_session()


@pytest.mark.asyncio
async def test_aiohttp_pins_the_ca() -> None:
    with serve(GOOD, GOOD_KEY) as server:
        node = _aiohttp_node(_port(server), ssl_assert_fingerprint=FINGERPRINT)
        try:
            meta, body = await node.perform_request("GET", "/")
            assert meta.status == 200
            assert body == b"ok"
            assert server.hits == 1
            assert server.auths == ["ApiKey secret"]
            assert node._ssl_context is not None
            assert node._ssl_context.check_hostname is False
            assert node._ssl_context.verify_mode == ssl.CERT_REQUIRED
        finally:
            await node.close()


def test_aiohttp_rejects_string_assert_hostname() -> None:
    with pytest.raises(ValueError, match="ssl_assert_hostname"):
        _aiohttp_node(
            1, ssl_assert_fingerprint=FINGERPRINT, ssl_assert_hostname="localhost"
        )


@pytest.mark.asyncio
async def test_aiohttp_presents_the_client_cert(tmp_path: Path) -> None:
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    cert.write_bytes(GOOD)
    key.write_bytes(GOOD_KEY)
    with serve(GOOD, GOOD_KEY, require_client=True) as server:
        node = _aiohttp_node(
            _port(server),
            ssl_assert_fingerprint=FINGERPRINT,
            client_cert=str(cert),
            client_key=str(key),
        )
        try:
            meta, _body = await node.perform_request("GET", "/")
            assert meta.status == 200
            assert server.hits == 1
        finally:
            await node.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("leaf", "key", "kwargs", "match"),
    [
        (FORGED, FORGED_KEY, {}, "signature|certificate|verify"),
        (EXPIRED, EXPIRED_KEY, {}, "expired"),
        (GOOD, GOOD_KEY, {"ssl_assert_fingerprint": "0" * 64}, "did not match"),
        (OTHER, OTHER_KEY, {"ssl_assert_hostname": True}, "mismatch"),
    ],
    ids=["forged", "expired", "wrong-fingerprint", "hostname-mismatch"],
)
async def test_aiohttp_rejection_sends_no_request(
    leaf: bytes, key: bytes, kwargs: dict, match: str
) -> None:
    kwargs = {"ssl_assert_fingerprint": FINGERPRINT, **kwargs}
    with serve(leaf, key) as server:
        node = _aiohttp_node(_port(server), **kwargs)
        try:
            with pytest.raises(TlsError, match=match):
                await node.perform_request("GET", "/")
            assert server.hits == 0
            assert server.auths == []
        finally:
            await node.close()


def test_invalid_length_message() -> None:
    with pytest.raises(ValueError) as exc:
        Urllib3HttpNode(
            NodeConfig("https", "localhost", 1, ssl_assert_fingerprint="0000")
        )
    assert (
        str(exc.value)
        == "Fingerprint of invalid length '4', should be one of '32', '40', '64'"
    )
