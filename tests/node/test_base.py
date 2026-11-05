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

import importlib
import ssl

import pytest

from elastic_transport import (
    AiohttpHttpNode,
    HttpxAsyncHttpNode,
    HttpxHttpNode,
    NodeConfig,
    RequestsHttpNode,
    Urllib3HttpNode,
)
from elastic_transport._node._base import ssl_context_from_node_config


@pytest.mark.parametrize(
    "node_cls",
    [
        Urllib3HttpNode,
        RequestsHttpNode,
        AiohttpHttpNode,
        HttpxHttpNode,
        HttpxAsyncHttpNode,
    ],
)
def test_unknown_parameter(node_cls):
    with pytest.raises(TypeError):
        node_cls(unknown_option=1)


@pytest.mark.parametrize(
    "host, check_hostname",
    [
        ("127.0.0.1", False),
        ("::1", False),
        ("localhost", True),
    ],
)
def test_ssl_context_from_node_config(host, check_hostname):
    node_config = NodeConfig("https", host, 443)
    ctx = ssl_context_from_node_config(node_config)
    assert ctx.check_hostname == check_hostname


def test_protocol_tlsv1_2_sets_minimum_version():
    if not hasattr(ssl, "PROTOCOL_TLSv1_2"):
        pytest.skip("PROTOCOL_TLSv1_2 is not defined")
    ctx = ssl_context_from_node_config(
        NodeConfig("https", "localhost", 9200, ssl_version=ssl.PROTOCOL_TLSv1_2)
    )
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_tls_version_without_protocol_constants():
    # OpenSSL 4 drops ssl.PROTOCOL_TLSv1*. TLSVersion members remain.
    import elastic_transport._node._base as base

    protocol_attrs = ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2")
    saved = {attr: getattr(ssl, attr) for attr in protocol_attrs if hasattr(ssl, attr)}
    for attr in saved:
        delattr(ssl, attr)
    try:
        importlib.reload(base)
        # Same construction path as an https client. verify_certs stays off
        # so this does not need a CA bundle.
        Urllib3HttpNode(
            NodeConfig(
                "https",
                "localhost",
                9200,
                verify_certs=False,
                ssl_show_warn=False,
            )
        )
        ctx = base.ssl_context_from_node_config(NodeConfig("https", "localhost", 9200))
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

        for version in (
            ssl.TLSVersion.TLSv1,
            ssl.TLSVersion.TLSv1_1,
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_3,
        ):
            ctx = base.ssl_context_from_node_config(
                NodeConfig("https", "localhost", 9200, ssl_version=version)
            )
            assert ctx.minimum_version == version

        with pytest.raises(ValueError, match="Unsupported value for 'ssl_version'"):
            base.ssl_context_from_node_config(
                NodeConfig("https", "localhost", 9200, ssl_version=0)
            )
    finally:
        for attr, value in saved.items():
            setattr(ssl, attr, value)
        importlib.reload(base)
