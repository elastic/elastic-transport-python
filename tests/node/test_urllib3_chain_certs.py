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
def test_ssl_assert_fingerprint_invalid_length(node_cls, httpbin_secure):
    with pytest.raises(ValueError) as e:
        node_cls(
            NodeConfig(
                "https",
                httpbin_secure.host,
                httpbin_secure.port,
                ssl_assert_fingerprint="0000",
            )
        )

    assert (
        str(e.value)
        == "Fingerprint of invalid length '4', should be one of '32', '40', '64'"
    )


@requires_ssl_assert_fingerprint_in_chain
@pytest.mark.parametrize("node_cls", [Urllib3HttpNode, RequestsHttpNode])
def test_assert_fingerprint_in_cert_chain(node_cls, cert_fingerprint, httpbin_secure):
    with warnings.catch_warnings(record=True) as w:
        node = node_cls(
            NodeConfig(
                "https",
                httpbin_secure.host,
                httpbin_secure.port,
                ssl_assert_fingerprint=cert_fingerprint,
            )
        )
        meta, _ = node.perform_request("GET", "/")
        assert meta.status == 200

    assert w == []


@requires_ssl_assert_fingerprint_in_chain
@pytest.mark.parametrize("node_cls", [Urllib3HttpNode, RequestsHttpNode])
def test_assert_fingerprint_in_cert_chain_failure(
    node_cls, httpbin_secure, cert_fingerprint
):
    node = node_cls(
        NodeConfig(
            "https",
            "www.elastic.co",
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
    # This is the root CA for www.elastic.co with a leading comma to denote more than one cert was listed.
    assert ', "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b"' in err
