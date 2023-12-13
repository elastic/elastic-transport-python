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

import io
import logging

import pytest

from elastic_transport import (
    AiohttpHttpNode,
    ConnectionError,
    HttpHeaders,
    RequestsHttpNode,
    Urllib3HttpNode,
    debug_logging,
)
from elastic_transport._compat import await_if_coro
from elastic_transport._node._base import DEFAULT_USER_AGENT

pytestmark = pytest.mark.asyncio


node_class = pytest.mark.parametrize(
    "node_class", [Urllib3HttpNode, RequestsHttpNode, AiohttpHttpNode]
)


@node_class
async def test_debug_logging(node_class, httpbin_node_config):
    debug_logging()

    stream = io.StringIO()
    logging.getLogger("elastic_transport.node").addHandler(
        logging.StreamHandler(stream)
    )

    node = node_class(httpbin_node_config)
    await await_if_coro(
        node.perform_request(
            "GET",
            "/anything",
            body=b'{"key":"value"}',
            headers=HttpHeaders({"Content-Type": "application/json"}),
        )
    )

    print(node_class)
    print(stream.getvalue())

    lines = stream.getvalue().split("\n")
    print(lines)
    for line in [
        "> GET /anything HTTP/1.1",
        "> Connection: keep-alive",
        "> Content-Type: application/json",
        f"> User-Agent: {DEFAULT_USER_AGENT}",
        '> {"key":"value"}',
        "< HTTP/1.1 200 OK",
        "< Access-Control-Allow-Credentials: true",
        "< Access-Control-Allow-Origin: *",
        "< Connection: close",
        "< Content-Type: application/json",
        "< {",
        '  "args": {}, ',
        '  "data": "{\\"key\\":\\"value\\"}", ',
        '  "files": {}, ',
        '  "form": {}, ',
        '  "headers": {',
        '    "Content-Type": "application/json", ',
        '    "Host": "httpbin.org", ',
        f'    "User-Agent": "{DEFAULT_USER_AGENT}", ',
        "  }, ",
        '  "json": {',
        '    "key": "value"',
        "  }, ",
        '  "method": "GET", ',
        '  "url": "https://httpbin.org/anything"',
        "}",
    ]:
        assert line in lines


@node_class
async def test_debug_logging_uncompressed_body(httpbin_node_config, node_class):
    debug_logging()
    stream = io.StringIO()
    logging.getLogger("elastic_transport.node").addHandler(
        logging.StreamHandler(stream)
    )

    node = node_class(httpbin_node_config.replace(http_compress=True))
    await await_if_coro(
        node.perform_request(
            "GET",
            "/anything",
            body=b'{"key":"value"}',
            headers=HttpHeaders({"Content-Type": "application/json"}),
        )
    )

    lines = stream.getvalue().split("\n")
    print(lines)
    assert '> {"key":"value"}' in lines


@node_class
async def test_debug_logging_no_body(httpbin_node_config, node_class):
    debug_logging()
    stream = io.StringIO()
    logging.getLogger("elastic_transport.node").addHandler(
        logging.StreamHandler(stream)
    )

    node = node_class(httpbin_node_config)
    await await_if_coro(
        node.perform_request(
            "HEAD",
            "/anything",
        )
    )

    lines = stream.getvalue().split("\n")[:-3]
    assert "> HEAD /anything HTTP/1.1" in lines


@node_class
async def test_debug_logging_error(httpbin_node_config, node_class):
    debug_logging()
    stream = io.StringIO()
    logging.getLogger("elastic_transport.node").addHandler(
        logging.StreamHandler(stream)
    )

    node = node_class(httpbin_node_config.replace(host="not.a.valid.host"))
    with pytest.raises(ConnectionError):
        await await_if_coro(
            node.perform_request(
                "HEAD",
                "/anything",
            )
        )

    lines = stream.getvalue().split("\n")[:-3]
    assert "> HEAD /anything HTTP/?.?" in lines
    assert all(not line.startswith("<") for line in lines)
