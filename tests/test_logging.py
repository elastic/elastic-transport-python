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
    ApiResponseMeta,
    ConnectionError,
    HttpHeaders,
    HttpxAsyncHttpNode,
    HttpxHttpNode,
    NodeConfig,
    RequestsHttpNode,
    Urllib3HttpNode,
    debug_logging,
)
from elastic_transport._compat import await_if_coro
from elastic_transport._node._base import DEFAULT_USER_AGENT

node_class = pytest.mark.parametrize(
    "node_class",
    [
        Urllib3HttpNode,
        RequestsHttpNode,
        AiohttpHttpNode,
        HttpxAsyncHttpNode,
        HttpxHttpNode,
    ],
)


@node_class
@pytest.mark.anyio
async def test_debug_logging(node_class, anyio_backend, httpbin_node_config, httpbin):
    if anyio_backend == "trio" and node_class is not HttpxAsyncHttpNode:
        pytest.skip("only httpx supports trio")

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

    response = stream.getvalue()
    print(response)
    for line in [
        "> GET /anything HTTP/1.1",
        "> Connection: keep-alive",
        "> Content-Type: application/json",
        f"> User-Agent: {DEFAULT_USER_AGENT}",
        '> {"key":"value"}',
        "< HTTP/1.1 200 OK",
        "< Access-Control-Allow-Credentials: true",
        "< Access-Control-Allow-Origin: *",
        "< Content-Type: application/json",
        "< {",
        '"args":{},',
        '"data":"{\\"key\\":\\"value\\"}",',
        '"files":{},',
        '"form":{},',
        '"headers":{',
        '"Content-Type":"application/json",',
        f'"Host":"{httpbin.host}:{httpbin.port}",',
        f'"User-Agent":"{DEFAULT_USER_AGENT}"',
        "},",
        '"json":{',
        '"key":"value"',
        "},",
        '"method":"GET",',
        f'"url":"{httpbin.url}/anything"',
        "}",
    ]:
        assert line in response


@node_class
@pytest.mark.anyio
async def test_debug_logging_uncompressed_body(
    httpbin_node_config, node_class, anyio_backend
):
    if anyio_backend == "trio" and node_class is not HttpxAsyncHttpNode:
        pytest.skip("only httpx supports trio")

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
@pytest.mark.anyio
async def test_debug_logging_no_body(httpbin_node_config, node_class, anyio_backend):
    if anyio_backend == "trio" and node_class is not HttpxAsyncHttpNode:
        pytest.skip("only httpx supports trio")

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
@pytest.mark.anyio
async def test_debug_logging_error(httpbin_node_config, node_class, anyio_backend):
    if anyio_backend == "trio" and node_class is not HttpxAsyncHttpNode:
        pytest.skip("only httpx supports trio")

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


def test_debug_logging_escapes_percent_in_headers():
    # A '%' in a header name or value must not be treated as a logging template
    # placeholder. '%' is a valid tchar in an HTTP field-name (RFC 9110), so a
    # server (or caller) can supply one; before escaping, the trailing
    # ``_logger.debug(fmt, *log_args)`` call raised inside logging while
    # interpolating, dropping the whole request/response line.
    node = Urllib3HttpNode(NodeConfig("http", "localhost", 9200))

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("elastic_transport.node")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        meta = ApiResponseMeta(
            status=200,
            http_version="1.1",
            # '%' in both a request header and a response header, in the name
            # (not covered by escaping only the value) as well as the value.
            headers=HttpHeaders({"X-%s%s-Trace": "100% ok"}),
            duration=0.0,
            node=node.config,
        )
        node._log_request(
            "GET",
            "/_search",
            headers=HttpHeaders({"X-Opaque-Id": "req-%d"}),
            body=None,
            meta=meta,
            response=b"{}",
        )
    finally:
        logger.removeHandler(handler)

    output = stream.getvalue()
    # The literal text must round-trip verbatim (no logging error, no mangling).
    assert "> X-Opaque-Id: req-%d" in output
    assert "< X-%S%S-Trace: 100% ok" in output
    assert "--- Logging error ---" not in output
