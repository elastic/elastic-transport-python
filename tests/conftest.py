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

import hashlib
import logging
import socket
import ssl

import pytest
import trustme
from pytest_httpserver import HTTPServer

from elastic_transport import ApiResponseMeta, BaseNode, HttpHeaders, NodeConfig
from elastic_transport._node import NodeApiResponse


class DummyNode(BaseNode):
    def __init__(self, config: NodeConfig):
        super().__init__(config)
        self.exception = config._extras.pop("exception", None)
        self.status = config._extras.pop("status", 200)
        self.body = config._extras.pop("body", b"{}")
        self.calls = []
        self._headers = config._extras.pop("headers", {})

    def perform_request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        meta = ApiResponseMeta(
            node=self.config,
            duration=0.0,
            http_version="1.1",
            status=self.status,
            headers=HttpHeaders(self._headers),
        )
        return NodeApiResponse(meta, self.body)


class AsyncDummyNode(DummyNode):
    async def perform_request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        meta = ApiResponseMeta(
            node=self.config,
            duration=0.0,
            http_version="1.1",
            status=self.status,
            headers=HttpHeaders(self._headers),
        )
        return NodeApiResponse(meta, self.body)


@pytest.fixture(scope="session", params=[True, False])
def httpbin_cert_fingerprint(request) -> str:
    """Gets the SHA256 fingerprint of the certificate for 'httpbin.org'"""
    sock = socket.create_connection(("httpbin.org", 443))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock)
    digest = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
    assert len(digest) == 64
    sock.close()
    if request.param:
        return digest
    else:
        return ":".join([digest[i : i + 2] for i in range(0, len(digest), 2)])


@pytest.fixture(scope="session")
def httpbin_node_config() -> NodeConfig:
    try:
        sock = socket.create_connection(("httpbin.org", 443))
    except Exception as e:
        pytest.skip(f"Couldn't connect to httpbin.org, internet not connected? {e}")
    sock.close()
    return NodeConfig(
        "https", "httpbin.org", 443, verify_certs=False, ssl_show_warn=False
    )


@pytest.fixture(scope="function", autouse=True)
def elastic_transport_logging():
    for name in ("node", "node_pool", "transport"):
        logger = logging.getLogger(f"elastic_transport.{name}")
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)


@pytest.fixture(scope="session")
def https_server_ip_node_config(tmp_path_factory: pytest.TempPathFactory) -> NodeConfig:
    ca = trustme.CA()
    tmpdir = tmp_path_factory.mktemp("certs")
    ca_cert_path = str(tmpdir / "ca.pem")
    ca.cert_pem.write_to_path(ca_cert_path)

    localhost_cert = ca.issue_cert("127.0.0.1")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    crt = localhost_cert.cert_chain_pems[0]
    key = localhost_cert.private_key_pem
    with crt.tempfile() as crt_file, key.tempfile() as key_file:
        context.load_cert_chain(crt_file, key_file)

    server = HTTPServer(ssl_context=context)
    server.expect_request("/foobar").respond_with_json({"foo": "bar"})

    server.start()
    yield NodeConfig("https", "127.0.0.1", server.port, ca_certs=ca_cert_path)
    server.clear()
    if server.is_running():
        server.stop()
