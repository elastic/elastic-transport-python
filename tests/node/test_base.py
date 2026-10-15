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

import runpy
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
from elastic_transport._node import _base
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


@pytest.mark.parametrize(
    "missing_protocols",
    [
        (),
        ("PROTOCOL_TLSv1",),
        ("PROTOCOL_TLSv1_1",),
        ("PROTOCOL_TLSv1_2",),
        ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2"),
    ],
)
@pytest.mark.parametrize(
    "ssl_version, minimum_version",
    [
        (None, ssl.TLSVersion.TLSv1_2),
        (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ],
)
def test_ssl_context_tls_versions_without_protocol_constants(
    monkeypatch, missing_protocols, ssl_version, minimum_version
):
    for protocol_attr in missing_protocols:
        monkeypatch.delattr(ssl, protocol_attr, raising=False)

    # Rebuild the import-time lookup tables without changing the imported module.
    module = runpy.run_path(_base.__file__, run_name=_base.__name__)
    node_config = NodeConfig("https", "localhost", 443, ssl_version=ssl_version)
    ctx = module["ssl_context_from_node_config"](node_config)
    assert ctx.minimum_version == minimum_version


@pytest.mark.parametrize(
    "protocol_attr, minimum_version",
    [
        ("PROTOCOL_TLSv1", ssl.TLSVersion.TLSv1),
        ("PROTOCOL_TLSv1_1", ssl.TLSVersion.TLSv1_1),
        ("PROTOCOL_TLSv1_2", ssl.TLSVersion.TLSv1_2),
    ],
)
def test_ssl_context_legacy_tls_versions(protocol_attr, minimum_version):
    if not hasattr(ssl, protocol_attr):
        pytest.skip(f"ssl.{protocol_attr} isn't available")

    node_config = NodeConfig(
        "https", "localhost", 443, ssl_version=getattr(ssl, protocol_attr)
    )
    ctx = ssl_context_from_node_config(node_config)
    assert ctx.minimum_version == minimum_version
