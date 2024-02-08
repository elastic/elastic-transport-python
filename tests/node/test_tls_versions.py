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

import functools
import socket
import ssl

import pytest

from elastic_transport import (
    AiohttpHttpNode,
    HttpxAsyncHttpNode,
    NodeConfig,
    RequestsHttpNode,
    TlsError,
    Urllib3HttpNode,
)
from elastic_transport._compat import await_if_coro
from elastic_transport.client_utils import url_to_node_config

TLSv1_0_URL = "https://tls-v1-0.badssl.com:1010"
TLSv1_1_URL = "https://tls-v1-1.badssl.com:1011"
TLSv1_2_URL = "https://tls-v1-2.badssl.com:1012"

node_classes = pytest.mark.parametrize(
    "node_class",
    [AiohttpHttpNode, Urllib3HttpNode, RequestsHttpNode, HttpxAsyncHttpNode],
)

supported_version_params = [
    (TLSv1_0_URL, ssl.PROTOCOL_TLSv1),
    (TLSv1_1_URL, ssl.PROTOCOL_TLSv1_1),
    (TLSv1_2_URL, ssl.PROTOCOL_TLSv1_2),
    (TLSv1_2_URL, None),
]
unsupported_version_params = [
    (TLSv1_0_URL, None),
    (TLSv1_1_URL, None),
    (TLSv1_0_URL, ssl.PROTOCOL_TLSv1_1),
    (TLSv1_0_URL, ssl.PROTOCOL_TLSv1_2),
    (TLSv1_1_URL, ssl.PROTOCOL_TLSv1_2),
]

try:
    from ssl import TLSVersion
except ImportError:
    pass
else:
    supported_version_params.extend(
        [
            (TLSv1_0_URL, TLSVersion.TLSv1),
            (TLSv1_1_URL, TLSVersion.TLSv1_1),
            (TLSv1_2_URL, TLSVersion.TLSv1_2),
        ]
    )
    unsupported_version_params.extend(
        [
            (TLSv1_0_URL, TLSVersion.TLSv1_1),
            (TLSv1_0_URL, TLSVersion.TLSv1_2),
            (TLSv1_1_URL, TLSVersion.TLSv1_2),
            (TLSv1_0_URL, TLSVersion.TLSv1_3),
            (TLSv1_1_URL, TLSVersion.TLSv1_3),
            (TLSv1_2_URL, TLSVersion.TLSv1_3),
        ]
    )


@functools.lru_cache()
def tlsv1_1_supported() -> bool:
    # OpenSSL distributions on Ubuntu/Debian disable TLSv1.1 and before incorrectly.
    # So we try to detect that and skip tests when needed.
    try:
        sock = socket.create_connection(("tls-v1-1.badssl.com", 1011))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
        sock = ctx.wrap_socket(sock, server_hostname="tls-v1-1.badssl.com")
        sock.close()
    except ssl.SSLError:
        return False
    return True


@node_classes
@pytest.mark.parametrize(
    ["url", "ssl_version"],
    supported_version_params,
)
@pytest.mark.asyncio
async def test_supported_tls_versions(node_class, url: str, ssl_version: int):
    if url in (TLSv1_0_URL, TLSv1_1_URL) and not tlsv1_1_supported():
        pytest.skip("TLSv1.1 isn't supported by this OpenSSL distribution")
    node_config = url_to_node_config(url).replace(ssl_version=ssl_version)
    node = node_class(node_config)

    resp, _ = await await_if_coro(node.perform_request("GET", "/"))
    assert resp.status == 200


@node_classes
@pytest.mark.parametrize(
    ["url", "ssl_version"],
    unsupported_version_params,
)
@pytest.mark.asyncio
async def test_unsupported_tls_versions(node_class, url: str, ssl_version: int):
    node_config = url_to_node_config(url).replace(ssl_version=ssl_version)
    node = node_class(node_config)

    with pytest.raises(TlsError) as e:
        await await_if_coro(node.perform_request("GET", "/"))
    assert "unsupported protocol" in str(e.value) or "handshake failure" in str(e.value)


@node_classes
@pytest.mark.parametrize("ssl_version", [0, "TLSv1", object()])
def test_ssl_version_value_error(node_class, ssl_version):
    with pytest.raises(ValueError) as e:
        node_class(NodeConfig("https", "localhost", 9200, ssl_version=ssl_version))
    assert str(e.value) == (
        f"Unsupported value for 'ssl_version': {ssl_version!r}. Must be either "
        "'ssl.PROTOCOL_TLSvX' or 'ssl.TLSVersion.TLSvX'"
    )
