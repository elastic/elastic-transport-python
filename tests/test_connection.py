# -*- coding: utf-8 -*-
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
import io
import re
import ssl
import warnings

import pytest
import requests
import urllib3
from mock import Mock, patch
from urllib3._collections import HTTPHeaderDict

from elastic_transport import (
    BadRequestError,
    ConflictError,
    ConnectionError,
    ConnectionTimeout,
    InternalServerError,
    NotFoundError,
    RequestsHttpConnection,
    TransportError,
    Urllib3HttpConnection,
)
from tests.conftest import norm_repr


def gzip_decompress(data):
    buf = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")
    return buf.read()


class TestUrllib3Connection(object):
    def _get_mock_connection(self, connection_params={}, response_body=b"{}"):
        con = Urllib3HttpConnection(**connection_params)

        def _dummy_urlopen(*args, **kwargs):
            dummy_response = Mock()
            dummy_response.headers = HTTPHeaderDict({})
            dummy_response.status = 200
            dummy_response.data = response_body
            _dummy_urlopen.call_args = (args, kwargs)
            return dummy_response

        con.pool.urlopen = _dummy_urlopen
        return con

    def test_close_pool(self):
        conn = Urllib3HttpConnection()
        with patch.object(conn.pool, "close") as pool_close:
            conn.close()
        pool_close.assert_called_with()

    def test_ssl_context(self):
        context = ssl.create_default_context()
        con = Urllib3HttpConnection(use_ssl=True, ssl_context=context)
        assert len(con.pool.conn_kw.keys()) == 1
        assert isinstance(con.pool.conn_kw["ssl_context"], ssl.SSLContext)
        assert con.use_ssl
        assert con.scheme == "https"

    def test_opaque_id(self):
        con = Urllib3HttpConnection(opaque_id="app-1")
        assert con.headers["x-opaque-id"] == "app-1"

    def test_user_agent(self):
        con = Urllib3HttpConnection(user_agent="user-agent")
        assert con.headers["user-agent"] == "user-agent"

        # User-Agent given via headers takes priority.
        con = Urllib3HttpConnection(
            user_agent="user-agent-1", headers={"user-agent": "user-agent-2"}
        )
        assert con.headers["user-agent"] == "user-agent-2"

    def test_no_http_compression(self):
        con = self._get_mock_connection()
        assert not con.http_compress
        assert "accept-encoding" not in con.headers

        con.perform_request("GET", "/")

        (_, _, req_body), kwargs = con.pool.urlopen.call_args

        assert not req_body
        assert "accept-encoding" not in kwargs["headers"]
        assert "content-encoding" not in kwargs["headers"]

    def test_http_compression(self):
        con = self._get_mock_connection({"http_compress": True})
        assert con.http_compress
        assert con.headers["accept-encoding"] == "gzip"

        # 'content-encoding' shouldn't be set at a connection level.
        # Should be applied only if the request is sent with a body.
        assert "content-encoding" not in con.headers

        con.perform_request("GET", "/", body=b"{}")

        (_, _, req_body), kwargs = con.pool.urlopen.call_args

        assert gzip_decompress(req_body) == b"{}"
        assert kwargs["headers"]["accept-encoding"] == "gzip"
        assert kwargs["headers"]["content-encoding"] == "gzip"

        con.perform_request("GET", "/")

        (_, _, req_body), kwargs = con.pool.urlopen.call_args

        assert not req_body
        assert kwargs["headers"]["accept-encoding"] == "gzip"
        assert "content-encoding" not in kwargs["headers"]

    @pytest.mark.parametrize("request_timeout", [42, None])
    def test_timeout_set(self, request_timeout):
        con = Urllib3HttpConnection(request_timeout=request_timeout)
        assert request_timeout == con.request_timeout

    def test_timeout_is_10_seconds_by_default(self):
        conn = Urllib3HttpConnection()
        assert conn.request_timeout == 10

        with patch.object(conn.pool, "urlopen") as pool_urlopen:
            resp = Mock()
            resp.status = 200
            resp.headers = {}
            pool_urlopen.return_value = resp

            conn.perform_request("GET", "/")
        _, kwargs = pool_urlopen.call_args

        # Using 'DEFAULT' will not override the HTTPSConnectionPool setting.
        assert "timeout" not in kwargs

    @pytest.mark.parametrize("request_timeout", [None, 15])
    def test_timeout_override_default(self, request_timeout):
        conn = Urllib3HttpConnection(request_timeout=5)
        assert conn.request_timeout == 5
        assert conn.pool.timeout.connect_timeout == 5
        assert conn.pool.timeout.read_timeout == 5

        with patch.object(conn.pool, "urlopen") as pool_urlopen:
            resp = Mock()
            resp.status = 200
            resp.headers = {}
            pool_urlopen.return_value = resp

            conn.perform_request("GET", "/", request_timeout=request_timeout)
        _, kwargs = pool_urlopen.call_args

        # Using 'DEFAULT' will not override the HTTPSConnectionPool setting.
        assert kwargs["timeout"] == request_timeout

    def test_keep_alive_is_on_by_default(self):
        con = Urllib3HttpConnection()
        assert {
            "connection": "keep-alive",
            "content-type": "application/json",
        } == con.headers

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = Urllib3HttpConnection(use_ssl=True, verify_certs=False)
            assert 1 == len(w)
            assert (
                "Connecting to 'https://localhost' using SSL with verify_certs=False is insecure"
                == str(w[0].message)
            )

        assert isinstance(con.pool, urllib3.HTTPSConnectionPool)

    def test_no_warn_when_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = Urllib3HttpConnection(
                use_ssl=True, verify_certs=False, ssl_show_warn=False
            )
            assert 0 == len(w)

        assert isinstance(con.pool, urllib3.HTTPSConnectionPool)

    def test_doesnt_use_https_if_not_specified(self):
        con = Urllib3HttpConnection()
        assert isinstance(con.pool, urllib3.HTTPConnectionPool)

    def test_no_warning_when_using_ssl_context(self):
        ctx = ssl.create_default_context()
        with warnings.catch_warnings(record=True) as w:
            Urllib3HttpConnection(ssl_context=ctx)
            assert 0 == len(w)

    def test_warns_if_using_non_default_ssl_kwargs_with_ssl_context(self):
        for kwargs in (
            {"ssl_show_warn": False},
            {"ssl_show_warn": True},
            {"verify_certs": True},
            {"verify_certs": False},
            {"ca_certs": "/path/to/certs"},
            {"ssl_show_warn": True, "ca_certs": "/path/to/certs"},
        ):
            kwargs["ssl_context"] = ssl.create_default_context()

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                Urllib3HttpConnection(**kwargs)

                assert 1 == len(w)
                assert (
                    "When using `ssl_context`, all other SSL related kwargs are ignored"
                    == str(w[0].message)
                )

    @patch("elastic_transport.connection.base.logger")
    def test_uncompressed_body_logged(self, logger):
        con = self._get_mock_connection(connection_params={"http_compress": True})
        con.perform_request("GET", "/", body=b'{"example": "body"}')

        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list

        assert '> {"example": "body"}' == req[0][0] % req[0][1:]
        assert "< {}" == resp[0][0] % resp[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_failed_request_logs(self, logger):
        conn = Urllib3HttpConnection()

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

        assert norm_repr(e.value) == "InternalServerError({'answer': 42}, status=500)"

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

    def test_surrogatepass_into_bytes(self):
        buf = b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"
        con = self._get_mock_connection(response_body=buf)
        status, headers, data = con.perform_request("GET", "/")
        assert u"你好\uda6a" == data


class TestRequestsConnection(object):
    def _get_mock_connection(
        self,
        connection_params={},
        status_code=200,
        response_headers={},
        response_body=b"{}",
        exception=None,
    ):
        con = RequestsHttpConnection(**connection_params)

        def _dummy_send(*args, **kwargs):
            dummy_response = Mock()
            dummy_response.headers = response_headers
            dummy_response.status_code = status_code
            dummy_response.content = response_body
            dummy_response.request = args[0]
            dummy_response.cookies = {}
            _dummy_send.call_args = (args, kwargs)
            if exception is not None:
                raise exception
            return dummy_response

        con.session.send = _dummy_send
        return con

    def _get_request(self, connection, *args, **kwargs):
        if "body" in kwargs:
            kwargs["body"] = kwargs["body"].encode("utf-8")

        status, headers, data = connection.perform_request(*args, **kwargs)
        assert 200 == status
        assert "{}" == data

        timeout = kwargs.pop("request_timeout", connection.request_timeout)
        args, kwargs = connection.session.send.call_args
        assert timeout == kwargs["timeout"]
        assert 1 == len(args)
        return args[0]

    @pytest.mark.parametrize("request_timeout", [42, None])
    def test_timeout_set(self, request_timeout):
        con = RequestsHttpConnection(request_timeout=request_timeout)
        assert request_timeout == con.request_timeout

    def test_opaque_id(self):
        con = RequestsHttpConnection(opaque_id="app-1")
        assert con.headers["x-opaque-id"] == "app-1"

    def test_user_agent(self):
        con = RequestsHttpConnection(user_agent="user-agent")
        assert con.headers["user-agent"] == "user-agent"

        # User-Agent given via headers takes priority.
        con = RequestsHttpConnection(
            user_agent="user-agent-1", headers={"user-agent": "user-agent-2"}
        )
        assert con.headers["user-agent"] == "user-agent-2"

    def test_no_http_compression(self):
        con = self._get_mock_connection()

        assert not con.http_compress
        assert "content-encoding" not in con.session.headers

        con.perform_request("GET", "/")

        req = con.session.send.call_args[0][0]
        assert "content-encoding" not in req.headers
        assert "accept-encoding" not in req.headers

    def test_http_compression(self):
        con = self._get_mock_connection(
            {"http_compress": True},
        )

        assert con.http_compress

        # 'content-encoding' shouldn't be set at a session level.
        # Should be applied only if the request is sent with a body.
        assert "content-encoding" not in con.session.headers

        con.perform_request("GET", "/", body=b"{}")

        req = con.session.send.call_args[0][0]
        assert req.headers["content-encoding"] == "gzip"
        assert req.headers["accept-encoding"] == "gzip"

        con.perform_request("GET", "/")

        req = con.session.send.call_args[0][0]
        assert "content-encoding" not in req.headers
        assert req.headers["accept-encoding"] == "gzip"

    def test_uses_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = self._get_mock_connection(
                {"use_ssl": True, "url_prefix": "url", "verify_certs": False}
            )
            assert 1 == len(w)
            assert (
                "Connecting to 'https://localhost/url' using SSL with verify_certs=False is insecure"
                == str(w[0].message)
            )

        request = self._get_request(con, "GET", "/")

        assert "https://localhost/url/" == request.url
        assert "GET" == request.method
        assert None is request.body

    def test_no_warn_when_using_https_if_verify_certs_is_off(self):
        with warnings.catch_warnings(record=True) as w:
            con = self._get_mock_connection(
                {
                    "use_ssl": True,
                    "url_prefix": "url",
                    "verify_certs": False,
                    "ssl_show_warn": False,
                }
            )
            assert 0 == len(w)

        request = self._get_request(con, "GET", "/")

        assert "https://localhost/url/" == request.url
        assert "GET" == request.method
        assert None is request.body

    def test_merge_headers(self):
        con = self._get_mock_connection(
            connection_params={"headers": {"h1": "v1", "h2": "v2"}}
        )
        req = self._get_request(con, "GET", "/", headers={"h2": "v2p", "h3": "v3"})
        assert req.headers["h1"] == "v1"
        assert req.headers["h2"] == "v2p"
        assert req.headers["h3"] == "v3"

    def test_default_headers(self):
        con = self._get_mock_connection()
        req = self._get_request(con, "GET", "/")
        assert req.headers["content-type"] == "application/json"

    def test_custom_headers(self):
        con = self._get_mock_connection()
        req = self._get_request(
            con,
            "GET",
            "/",
            headers={
                "content-type": "application/x-ndjson",
                "user-agent": "custom-agent/1.2.3",
            },
        )
        assert req.headers["content-type"] == "application/x-ndjson"
        assert req.headers["user-agent"] == "custom-agent/1.2.3"

    def test_repr(self):
        con = self._get_mock_connection({"host": "elasticsearch.com", "port": 443})
        assert "<RequestsHttpConnection: http://elasticsearch.com:443>" == repr(con)

    def test_conflict_error_is_returned_on_409(self):
        con = self._get_mock_connection(status_code=409)
        with pytest.raises(ConflictError):
            con.perform_request("GET", "/", {}, "")

    def test_not_found_error_is_returned_on_404(self):
        con = self._get_mock_connection(status_code=404)
        with pytest.raises(NotFoundError):
            con.perform_request("GET", "/", {}, "")

    def test_request_error_is_returned_on_400(self):
        con = self._get_mock_connection(status_code=400)
        with pytest.raises(BadRequestError):
            con.perform_request("GET", "/", {}, "")

    @patch("elastic_transport.connection.base.logger")
    def test_head_with_404_doesnt_get_logged(self, logger):
        con = self._get_mock_connection(status_code=404)
        with pytest.raises(NotFoundError):
            con.perform_request("HEAD", "/", {}, "")
        assert 0 == logger.warning.call_count

    @patch("elastic_transport.connection.base.logger")
    def test_failed_request_logs(self, logger):
        con = self._get_mock_connection(
            response_body=b'{"answer": 42}', status_code=500
        )
        with pytest.raises(TransportError) as e:
            con.perform_request(
                "GET",
                "/?param=42",
                b"{}",
            )
        assert norm_repr(e.value) == "InternalServerError({'answer': 42}, status=500)"

        # log url and duration
        assert 1 == logger.warning.call_count
        assert re.match(
            r"^GET http://localhost/\?param=42 \[status:500 request:0.[0-9]{3}s\]",
            logger.warning.call_args[0][0] % logger.warning.call_args[0][1:],
        )
        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list
        assert "> {}" == req[0][0] % req[0][1:]
        assert '< {"answer": 42}' == resp[0][0] % resp[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_failed_request_not_json(self, logger):
        con = self._get_mock_connection(
            response_body=b"this is a plaintext error",
            response_headers={"content-type": "text/plain"},
            status_code=500,
        )
        with pytest.raises(TransportError) as e:
            con.perform_request(
                "GET",
                "/?param=42",
                b"{}",
            )
        assert e.value.message == "this is a plaintext error"
        assert e.value.status == 500
        assert (
            norm_repr(e.value)
            == "InternalServerError('this is a plaintext error', status=500)"
        )

        # log url and duration
        assert 1 == logger.warning.call_count
        assert re.match(
            r"^GET http://localhost/\?param=42 \[status:500 request:0.[0-9]{3}s\]",
            logger.warning.call_args[0][0] % logger.warning.call_args[0][1:],
        )
        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list
        assert "> {}" == req[0][0] % req[0][1:]
        assert "< this is a plaintext error" == resp[0][0] % resp[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_exception_request_logs(self, logger):
        con = self._get_mock_connection(
            exception=requests.ConnectionError("connection error!")
        )
        with pytest.raises(ConnectionError) as e:
            con.perform_request(
                "GET",
                "/?param=42",
                b"{}",
            )
        assert norm_repr(
            e.value
        ) == "ConnectionError('connection error!', errors=%r)" % (e.value.errors,)

        # log url and duration
        assert 1 == logger.warning.call_count
        assert re.match(
            r"^GET http://localhost/\?param=42 \[status:N/A request:0.[0-9]{3}s\]",
            logger.warning.call_args[0][0] % logger.warning.call_args[0][1:],
        )
        assert 1 == logger.debug.call_count
        (req,) = logger.debug.call_args_list
        assert "> {}" == req[0][0] % req[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_timeout_exception_request_logs(self, logger):
        con = self._get_mock_connection(exception=requests.Timeout("timeout error!"))
        with pytest.raises(ConnectionTimeout) as e:
            con.perform_request(
                "GET",
                "/?param=42",
                b"{}",
            )
        assert norm_repr(
            e.value
        ) == "ConnectionTimeout('Connection timed out during request', errors=%r)" % (
            e.value.errors,
        )

        # log url and duration
        assert 1 == logger.warning.call_count
        assert re.match(
            r"^GET http://localhost/\?param=42 \[status:N/A request:0.[0-9]{3}s\]",
            logger.warning.call_args[0][0] % logger.warning.call_args[0][1:],
        )
        assert 1 == logger.debug.call_count
        (req,) = logger.debug.call_args_list
        assert "> {}" == req[0][0] % req[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_success_logs(self, logger):
        con = self._get_mock_connection(response_body=b"""{"answer": "that's it!"}""")
        con.perform_request(
            "GET",
            "/?param=42",
            """{"question": "what's that?"}""".encode("utf-8"),
        )

        # log url and duration
        assert 1 == logger.info.call_count
        assert re.match(
            r"GET http://localhost/\?param=42 \[status:200 request:0.[0-9]{3}s\]",
            logger.info.call_args[0][0] % logger.info.call_args[0][1:],
        )
        # log request body and response
        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list
        assert '> {"question": "what\'s that?"}' == req[0][0] % req[0][1:]
        assert '< {"answer": "that\'s it!"}' == resp[0][0] % resp[0][1:]

    @patch("elastic_transport.connection.base.logger")
    def test_uncompressed_body_logged(self, logger):
        con = self._get_mock_connection(connection_params={"http_compress": True})
        con.perform_request("GET", "/", body=b'{"example": "body"}')

        assert 2 == logger.debug.call_count
        req, resp = logger.debug.call_args_list
        assert '> {"example": "body"}' == req[0][0] % req[0][1:]
        assert "< {}" == resp[0][0] % resp[0][1:]

        con = self._get_mock_connection(
            connection_params={"http_compress": True},
            status_code=500,
            response_body=b'{"hello":"world"}',
        )
        with pytest.raises(InternalServerError):
            con.perform_request("GET", "/", body=b'{"example": "body2"}')

        assert 4 == logger.debug.call_count
        _, _, req, resp = logger.debug.call_args_list
        assert '> {"example": "body2"}' == req[0][0] % req[0][1:]
        assert '< {"hello":"world"}' == resp[0][0] % resp[0][1:]

    def test_defaults(self):
        con = self._get_mock_connection()
        request = self._get_request(con, "GET", "/")

        assert "http://localhost/" == request.url
        assert con.port is None
        assert con.host == "localhost"
        assert "GET" == request.method
        assert None is request.body

    def test_body_attached(self):
        con = self._get_mock_connection()
        request = self._get_request(con, "GET", "/", body='{"answer": 42}')

        assert "http://localhost/" == request.url
        assert "GET" == request.method
        assert '{"answer": 42}'.encode("utf-8") == request.body

    @patch("elastic_transport.connection.base.logger")
    def test_url_prefix(self, logger):
        con = self._get_mock_connection({"url_prefix": "/some-prefix/", "port": 3002})
        request = self._get_request(
            con, "GET", "/_search", body='{"answer": 42}', request_timeout=0.1
        )

        assert "http://localhost:3002/some-prefix/_search" == request.url
        assert "GET" == request.method
        assert '{"answer": 42}'.encode("utf-8") == request.body

        assert 1 == logger.info.call_count
        assert re.match(
            r"GET http://localhost:3002/some-prefix/_search \[status:200 request:0\.[0-9]{3}s]",
            logger.info.call_args[0][0] % logger.info.call_args[0][1:],
        )

    def test_surrogatepass_into_bytes(self):
        buf = b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"
        con = self._get_mock_connection(response_body=buf)
        status, headers, data = con.perform_request("GET", "/")
        assert u"你好\uda6a" == data

    def test_client_cert_is_used_as_session_cert(self):
        conn = RequestsHttpConnection(
            client_cert="/client/cert", client_key="/client/key"
        )
        assert conn.session.cert == ("/client/cert", "/client/key")

    def test_ca_certs_is_used_as_session_verify(self):
        conn = RequestsHttpConnection(ca_certs="/ca/certs")
        assert conn.session.verify == "/ca/certs"

    def test_ca_certs_with_verify_ssl_false_raises_error(self):
        with pytest.raises(ValueError) as e:
            RequestsHttpConnection(ca_certs="/ca/certs", verify_certs=False)
        assert str(e.value) == "You cannot pass CA certificates when verify_ssl=False."

    def test_closing_connection_closes_session(self):
        conn = RequestsHttpConnection()
        with patch.object(conn.session, "close") as session_close:
            conn.close()
        session_close.assert_called_with()
