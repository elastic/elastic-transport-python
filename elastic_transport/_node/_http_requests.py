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

import time
import warnings
from typing import Tuple

import urllib3

from .._exceptions import ConnectionError, ConnectionTimeout
from .._models import HttpHeaders, HttpResponse
from ..utils import DEFAULT, client_meta_version, normalize_headers
from ._base import BaseNode

try:
    import requests
    from requests.adapters import HTTPAdapter

    _REQUESTS_AVAILABLE = True
    _REQUESTS_META_VERSION = client_meta_version(requests.__version__)
except ImportError:  # pragma: nocover
    _REQUESTS_AVAILABLE = False
    _REQUESTS_META_VERSION = ""


class RequestsHttpNode(BaseNode):
    """
    Connection using the `requests` library communicating via HTTP.

    :arg use_ssl: use ssl for the connection if `True`
    :arg verify_certs: whether to verify SSL certificates
    :arg ssl_show_warn: show warning when verify certs is disabled
    :arg ca_certs: optional path to CA bundle. By default standard requests'
        bundle will be used.
    :arg client_cert: path to the file containing the private key and the
        certificate, or cert only if using client_key
    :arg client_key: path to the file containing the private key if using
        separate cert and key files (client_cert will contain only the cert)
    :arg headers: any custom http headers to be add to requests
    :arg http_compress: Use gzip compression
    :arg opaque_id: Send this value in the 'X-Opaque-Id' HTTP header
        For tracing all requests made by this transport.
    """

    _ELASTIC_CLIENT_META = ("rq", _REQUESTS_META_VERSION)

    def __init__(
        self,
        host="localhost",
        port=None,
        use_ssl=False,
        verify_certs=True,
        ssl_show_warn=True,
        ca_certs=None,
        client_cert=None,
        client_key=None,
        connections_per_node=10,
        headers=None,
        http_compress=None,
        opaque_id=None,
        **kwargs,
    ):
        if not _REQUESTS_AVAILABLE:  # pragma: nocover
            raise ValueError(
                "You must have 'requests' installed to use RequestsHttpConnection"
            )

        # Initialize Session so .headers works before calling super().__init__().
        self.session = requests.Session()
        # Empty out all the default session headers except 'Connection: keep-alive'
        for key in list(self.session.headers):
            if key.lower() == "connection":
                continue
            self.session.headers.pop(key)

        super().__init__(
            host=host,
            port=port,
            use_ssl=use_ssl,
            headers=headers,
            http_compress=http_compress,
            opaque_id=opaque_id,
            **kwargs,
        )

        self.session.verify = verify_certs
        if not client_key:
            self.session.cert = client_cert
        elif client_cert:
            # cert is a tuple of (certfile, keyfile)
            self.session.cert = (client_cert, client_key)
        if ca_certs:
            if not verify_certs:
                raise ValueError(
                    "You cannot pass CA certificates when verify_ssl=False."
                )
            self.session.verify = ca_certs

        if not ssl_show_warn:
            urllib3.disable_warnings()

        if self.use_ssl and not verify_certs and ssl_show_warn:
            warnings.warn(
                f"Connecting to {self.base_url!r} using SSL with verify_certs=False is insecure"
            )

        # Create and mount custom adapter for constraining number of connections
        adapter = HTTPAdapter(
            pool_connections=connections_per_node,
            pool_maxsize=connections_per_node,
            pool_block=True,
        )
        for prefix in ("http://", "https://"):
            self.session.mount(prefix=prefix, adapter=adapter)

    def perform_request(
        self,
        method,
        target,
        body=None,
        request_timeout=DEFAULT,
        ignore_status=(),
        headers=None,
    ) -> Tuple[HttpResponse, bytes]:
        url = self.base_url + target
        headers = normalize_headers(headers)

        if self.http_compress and body:
            body = self._gzip_compress(body)
            headers["content-encoding"] = "gzip"

        start = time.time()
        request = requests.Request(method=method, headers=headers, url=url, data=body)
        prepared_request = self.session.prepare_request(request)
        send_kwargs = {
            "timeout": request_timeout
            if request_timeout is not DEFAULT
            else self.request_timeout
        }
        send_kwargs.update(
            self.session.merge_environment_settings(
                prepared_request.url, {}, None, None, None
            )
        )
        try:
            response = self.session.send(prepared_request, **send_kwargs)
            data = response.content
            duration = time.time() - start
            response_headers = HttpHeaders(response.headers)
        except Exception as e:
            if isinstance(e, requests.Timeout):
                raise ConnectionTimeout(
                    "Connection timed out during request", errors=(e,)
                )
            raise ConnectionError(str(e), errors=(e,))

        response = HttpResponse(
            duration=duration,
            version="1.1",
            status=response.status_code,
            headers=response_headers,
        )
        return response, data

    @property
    def headers(self):
        return self.session.headers

    def close(self):
        """
        Explicitly closes connections
        """
        self.session.close()
