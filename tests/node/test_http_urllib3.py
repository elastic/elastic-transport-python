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
import re
import ssl
import warnings
from unittest.mock import Mock, patch

import pytest
import urllib3
from urllib3.response import HTTPHeaderDict

from elastic_transport import NodeConfig, TransportError, Urllib3HttpNode
from elastic_transport._node._base import DEFAULT_USER_AGENT


class TestUrllib3HttpNode:
    def _get_mock_node(self, node_config, response_body=b"{}"):
        node = Urllib3HttpNode(node_config)

        def _dummy_urlopen(*args, **kwargs):
            dummy_response = Mock()
            dummy_response.headers = HTTPHeaderDict({})
            dummy_response.status = 200
            dummy_response.data = response_body
            _dummy_urlopen.call_args = (args, kwargs)
            return dummy_response

        node.pool.urlopen = _dummy_urlopen
        return node

    def test_close_pool(self):
        node = Urllib3HttpNode(NodeConfig("http", "localhost", 80))
        with patch.object(node.pool, "close") as pool_close:
            node.close()
        pool_close.assert_called_with()

    def test_ssl_context(self):
        ctx = ssl.create_default_context()
        node = Urllib3HttpNode(NodeConfig("https", "localhost", 80, ssl_context=ctx))
        assert len(node.pool.conn_kw.keys()) == 1
        assert isinstance(node.pool.conn_kw["ssl_context"], ssl.SSLContext)
        assert node.scheme == "https"

    def test_no_http_compression(self):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, http_compress=False)
        )
        assert not node.config.http_compress
        assert "accept-encoding" not in node.headers

        node.perform_request("GET", "/")
        (_, _), kwargs = node.pool.urlopen.call_args

        assert kwargs["body"] is None
        assert "accept-encoding" not in kwargs["headers"]
        assert "content-encoding" not in kwargs["headers"]

        node.perform_request("GET", "/", body=b"hello, world!")
        (_, _), kwargs = node.pool.urlopen.call_args

        assert kwargs["body"] == b"hello, world!"
        assert "accept-encoding" not in kwargs["headers"]
        assert "content-encoding" not in kwargs["headers"]

    @pytest.mark.parametrize(
        ["request_target", "expected_target"],
        [
            ("/_search", "/prefix/_search"),
            ("/?key=val", "/prefix/?key=val"),
            ("/_search?key=val/", "/prefix/_search?key=val/"),
        ],
    )
    def test_path_prefix_applied_to_target(self, request_target, expected_target):
        node = self._get_mock_node(
            NodeConfig("http", "localhost", 80, path_prefix="/prefix")
        )

        node.perform_request("GET", request_target)
        (_, target), _ = node.pool.urlopen.call_args

        assert target == expected_target

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

        (_, _), kwargs = node.pool.urlopen.call_args

        body = kwargs["body"]
        assert gzip.decompress(body) == b"{}"
        assert kwargs["headers"]["accept-encoding"] == "gzip"
        assert kwargs["headers"]["content-encoding"] == "gzip"

        node.perform_request("GET", "/", body=empty_body)

        (_, _), kwargs = node.pool.urlopen.call_args

        assert kwargs["body"] is None
        assert kwargs["headers"]["accept-encoding"] == "gzip"
        assert "content-encoding" not in kwargs["headers"]

    def test_default_headers(self):
        node = self._get_mock_node(NodeConfig("http", "localhost", 80))
        node.perform_request("GET", "/")
        (_, _), kwargs = node.pool.urlopen.call_args
        assert kwargs["headers"] == {
            "connection": "keep-alive",
            "user-agent": DEFAULT_USER_AGENT,
        }

    @pytest.mark.parametrize("request_timeout", [None, 15])
    def test_timeout_override_default(self, request_timeout):
        node = Urllib3HttpNode(
            NodeConfig("http", "localhost", 80, request_timeout=request_timeout)
        )
        assert node.config.request_timeout == request_timeout
        assert node.pool.timeout.total == request_timeout

        with patch.object(node.pool, "urlopen") as pool_urlopen:
            resp = Mock()
            resp.status = 200
            resp.headers = {}
            pool_urlopen.return_value = resp

            node.perform_request("GET", "/", request_timeout=request_timeout)
        _, kwargs = pool_urlopen.call_args

        assert kwargs["timeout"] == request_timeout

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = Urllib3HttpNode(
                NodeConfig("https", "localhost", 443, verify_certs=False)
            )
            assert 1 == len(w)
            assert (
                "Connecting to 'https://localhost:443' using TLS with verify_certs=False is insecure"
                == str(w[0].message)
            )

        assert isinstance(con.pool, urllib3.HTTPSConnectionPool)

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = Urllib3HttpNode(
                NodeConfig(
                    "https", "localhost", 443, verify_certs=False, ssl_show_warn=False
                )
            )

        assert 0 == len(w)
        assert isinstance(con.pool, urllib3.HTTPSConnectionPool)

    def test_no_warning_when_using_ssl_context(self):
        ctx = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            Urllib3HttpNode(NodeConfig("https", "localhost", 443, ssl_context=ctx))
        assert 0 == len(w)

    def test_surrogatepass_into_bytes(self):
        data = b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"
        con = self._get_mock_node(
            NodeConfig("http", "localhost", 80), response_body=data
        )
        _, data = con.perform_request("GET", "/")
        assert b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa" == data

    @pytest.mark.xfail
    @patch("elastic_transport._node._base.logger")
    def test_uncompressed_body_logged(self, logger):
        con = self._get_mock_node(connection_params={"http_compress": True})
        con.perform_request("GET", "/", body=b'{"example": "body"}')

        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list

        assert '> {"example": "body"}' == req[0][0] % req[0][1:]
        assert "< {}" == resp[0][0] % resp[0][1:]

    @pytest.mark.xfail
    @patch("elastic_transport._node._base.logger")
    def test_failed_request_logs(self, logger):
        conn = Urllib3HttpNode()

        with patch.object(conn.pool, "urlopen") as pool_urlopen:
            resp = Mock()
            resp.data = b'{"answer":42}'
            resp.status = 500
            resp.headers = {}
            pool_urlopen.return_value = resp

            with pytest.raises(TransportError) as e:
                conn.perform_request(
                    "GET",
                    "/?param=42",
                    b"{}",
                )

        assert repr(e.value) == "InternalServerError({'answer': 42}, status=500)"

        # log url and duration
        assert 1 == logger.warning.call_count
        assert re.match(
            r"^GET http://localhost/\?param=42 \[status:500 request:0.[0-9]{3}s\]",
            logger.warning.call_args[0][0] % logger.warning.call_args[0][1:],
        )
        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list
        assert "> {}" == req[0][0] % req[0][1:]
        assert '< {"answer":42}' == resp[0][0] % resp[0][1:]
