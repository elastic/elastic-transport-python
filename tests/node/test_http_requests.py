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

import gzip
import ssl
import warnings
from unittest.mock import Mock, patch

import pytest
import requests
from requests.auth import HTTPBasicAuth

from elastic_transport import NodeConfig, RequestsHttpNode
from elastic_transport._node._base import DEFAULT_USER_AGENT


class TestRequestsHttpNode:
    def _get_mock_node(self, node_config, response_body=b"{}"):
        node = RequestsHttpNode(node_config)

        def _dummy_send(*args, **kwargs):
            dummy_response = Mock()
            dummy_response.headers = {}
            dummy_response.status_code = 200
            dummy_response.content = response_body
            dummy_response.request = args[0]
            dummy_response.cookies = {}
            _dummy_send.call_args = (args, kwargs)
            return dummy_response

        node.session.send = _dummy_send
        return node

    def _get_request(self, node, *args, **kwargs) -> requests.PreparedRequest:
        resp, data = node.perform_request(*args, **kwargs)
        status = resp.status
        assert 200 == status
        assert b"{}" == data

        timeout = kwargs.pop("request_timeout", node.config.request_timeout)
        args, kwargs = node.session.send.call_args
        assert timeout == kwargs["timeout"]
        assert 1 == len(args)
        return args[0]

    def test_close_session(self):
        node = RequestsHttpNode(NodeConfig("http", "localhost", 80))
        with patch.object(node.session, "close") as pool_close:
            node.close()
        pool_close.assert_called_with()

    def test_ssl_context(self):
        ctx = ssl.create_default_context()
        node = RequestsHttpNode(NodeConfig("https", "localhost", 80, ssl_context=ctx))
        adapter = node.session.get_adapter("https://localhost:80")
        assert adapter.poolmanager.connection_pool_kw["ssl_context"] is ctx

    def test_merge_headers(self):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, headers={"h1": "v1", "h2": "v2"})
        )
        req = self._get_request(node, "GET", "/", headers={"h2": "v2p", "h3": "v3"})
        assert req.headers["h1"] == "v1"
        assert req.headers["h2"] == "v2p"
        assert req.headers["h3"] == "v3"

    def test_default_headers(self):
        node = self._get_mock_node(NodeConfig("http", "localhost", 80))
        req = self._get_request(node, "GET", "/")
        assert req.headers == {
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }

    def test_no_http_compression(self):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, http_compress=False)
        )
        assert not node.config.http_compress
        assert "accept-encoding" not in node.headers

        node.perform_request("GET", "/")
        (req,), _ = node.session.send.call_args

        assert req.body is None
        assert "accept-encoding" not in req.headers
        assert "content-encoding" not in req.headers

        node.perform_request("GET", "/", body=b"hello, world!")
        (req,), _ = node.session.send.call_args

        assert req.body == b"hello, world!"
        assert "accept-encoding" not in req.headers
        assert "content-encoding" not in req.headers

    @pytest.mark.parametrize("empty_body", [None, b""])
    def test_http_compression(self, empty_body):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, http_compress=True)
        )
        assert node.config.http_compress is True
        assert node.headers["accept-encoding"] == "gzip"

        # 'content-encoding' shouldn't be set at a connection level.
        # Should be applied only if the request is sent with a body.
        assert "content-encoding" not in node.headers

        node.perform_request("GET", "/", body=b"{}")
        (req,), _ = node.session.send.call_args

        assert gzip.decompress(req.body) == b"{}"
        assert req.headers["accept-encoding"] == "gzip"
        assert req.headers["content-encoding"] == "gzip"

        node.perform_request("GET", "/", body=empty_body)
        (req,), _ = node.session.send.call_args

        assert req.body is None
        assert req.headers["accept-encoding"] == "gzip"
        print(req.headers)
        assert "content-encoding" not in req.headers

    @pytest.mark.parametrize("request_timeout", [None, 15])
    def test_timeout_override_default(self, request_timeout):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, request_timeout=request_timeout)
        )
        assert node.config.request_timeout == request_timeout

        node.perform_request("GET", "/")
        _, kwargs = node.session.send.call_args

        assert kwargs["timeout"] == request_timeout

        node.perform_request("GET", "/", request_timeout=5)
        _, kwargs = node.session.send.call_args

        assert kwargs["timeout"] == 5

        node.perform_request("GET", "/", request_timeout=None)
        _, kwargs = node.session.send.call_args

        assert kwargs["timeout"] is None

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            RequestsHttpNode(NodeConfig("https", "localhost", 443, verify_certs=False))

        assert 1 == len(w)
        assert (
            "Connecting to 'https://localhost:443' using TLS with verify_certs=False is insecure"
            == str(w[0].message)
        )

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            RequestsHttpNode(
                NodeConfig(
                    "https", "localhost", 443, verify_certs=False, ssl_show_warn=False
                )
            )
        assert 0 == len(w)

    def test_no_warning_when_using_ssl_context(self):
        ctx = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            RequestsHttpNode(NodeConfig("https", "localhost", 443, ssl_context=ctx))
        assert 0 == len(w)

    def test_ca_certs_with_verify_ssl_false_raises_error(self):
        with pytest.raises(ValueError) as e:
            RequestsHttpNode(
                NodeConfig(
                    "https", "localhost", 443, ca_certs="/ca/certs", verify_certs=False
                )
            )
        assert str(e.value) == "You cannot use 'ca_certs' when 'verify_certs=False'"

    def test_client_cert_is_used_as_session_cert(self):
        conn = RequestsHttpNode(
            NodeConfig("https", "localhost", 443, client_cert="/client/cert")
        )
        assert conn.session.cert == "/client/cert"

        conn = RequestsHttpNode(
            NodeConfig(
                "https",
                "localhost",
                443,
                client_cert="/client/cert",
                client_key="/client/key",
            )
        )
        assert conn.session.cert == ("/client/cert", "/client/key")

    def test_ca_certs_is_used_as_session_verify(self):
        conn = RequestsHttpNode(
            NodeConfig("https", "localhost", 443, ca_certs="/ca/certs")
        )
        assert conn.session.verify == "/ca/certs"

    def test_surrogatepass_into_bytes(self):
        data = b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80), response_body=data
        )
        _, data = node.perform_request("GET", "/")
        assert b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa" == data

    @pytest.mark.parametrize("_extras", [None, {}, {"requests.session.auth": None}])
    def test_requests_no_session_auth(self, _extras):
        node = self._get_mock_node(NodeConfig("http", "localhost", 80, _extras=_extras))
        assert node.session.auth is None

    def test_requests_custom_auth(self):
        auth = HTTPBasicAuth("username", "password")
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, _extras={"requests.session.auth": auth})
        )
        assert node.session.auth is auth
        node.perform_request("GET", "/")
        (request,), _ = node.session.send.call_args
        assert request.headers["authorization"] == "Basic dXNlcm5hbWU6cGFzc3dvcmQ="
