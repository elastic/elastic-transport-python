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

import sys
import warnings

import pytest

from elastic_transport import NodeConfig, RequestsHttpNode, TlsError, Urllib3HttpNode

requires_ssl_assert_fingerprint_in_chain = pytest.mark.skipif(
    sys.version_info < (3, 10) or sys.implementation.name != "cpython",
    reason="Requires CPython 3.10+",
)


@requires_ssl_assert_fingerprint_in_chain
@pytest.mark.parametrize("node_cls", [Urllib3HttpNode, RequestsHttpNode])
def test_ssl_assert_fingerprint_invalid_length(node_cls):
    with pytest.raises(ValueError) as e:
        node_cls(
            NodeConfig(
                "https",
                "httpbin.org",
                443,
                ssl_assert_fingerprint="0000",
            )
        )

    assert (
        str(e.value)
        == "Fingerprint of invalid length '4', should be one of '32', '40', '64'"
    )


@requires_ssl_assert_fingerprint_in_chain
@pytest.mark.parametrize("node_cls", [Urllib3HttpNode, RequestsHttpNode])
@pytest.mark.parametrize(
    "ssl_assert_fingerprint",
    [
        "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
        "8e:cd:e6:88:4f:3d:87:b1:12:5b:a3:1a:c3:fc:b1:3d:70:16:de:7f:57:cc:90:4f:e1:cb:97:c6:ae:98:19:6e",
        "8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E",
    ],
)
def test_assert_fingerprint_in_cert_chain(node_cls, ssl_assert_fingerprint):
    with warnings.catch_warnings(record=True) as w:
        node = node_cls(
            NodeConfig(
                "https",
                "httpbin.org",
                443,
                ssl_assert_fingerprint=ssl_assert_fingerprint,
            )
        )
        meta, _ = node.perform_request("GET", "/")
        assert meta.status == 200

    assert w == []


@requires_ssl_assert_fingerprint_in_chain
@pytest.mark.parametrize("node_cls", [Urllib3HttpNode, RequestsHttpNode])
def test_assert_fingerprint_in_cert_chain_failure(node_cls):
    node = node_cls(
        NodeConfig(
            "https",
            "httpbin.org",
            443,
            ssl_assert_fingerprint="0" * 64,
        )
    )

    with pytest.raises(TlsError) as e:
        node.perform_request("GET", "/")

    err = str(e.value)
    assert "Fingerprints did not match." in err
    # This is the bad value we "expected"
    assert (
        'Expected "0000000000000000000000000000000000000000000000000000000000000000",'
        in err
    )
    # This is the root CA for httpbin.org with a leading comma to denote more than one cert was listed.
    assert ', "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e"' in err
