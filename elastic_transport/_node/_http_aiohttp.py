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

import asyncio
import base64
import functools
import os
import ssl
import warnings
from typing import Tuple

from .._compat import get_running_loop
from .._exceptions import ConnectionError, ConnectionTimeout, SecurityWarning, TlsError
from .._models import HttpHeaders, HttpResponse
from ..utils import DEFAULT, client_meta_version, normalize_headers
from ._base import DEFAULT_CA_CERTS, RERAISE_EXCEPTIONS
from ._base_async import BaseAsyncNode

try:
    import aiohttp
    import aiohttp.client_exceptions as aiohttp_exceptions

    _AIOHTTP_AVAILABLE = True
    _AIOHTTP_META_VERSION = client_meta_version(aiohttp.__version__)
except ImportError:  # pragma: nocover
    _AIOHTTP_AVAILABLE = False
    _AIOHTTP_META_VERSION = ""


class AiohttpHttpNode(BaseAsyncNode):
    _ELASTIC_CLIENT_META = ("ai", _AIOHTTP_META_VERSION)

    def __init__(
        self,
        host="localhost",
        port=None,
        use_ssl=False,
        verify_certs=DEFAULT,
        ssl_show_warn=DEFAULT,
        ca_certs=None,
        client_cert=None,
        client_key=None,
        ssl_version=None,
        ssl_assert_hostname=None,
        ssl_assert_fingerprint=None,
        connections_per_node=10,
        headers=None,
        ssl_context=None,
        http_compress=None,
        opaque_id=None,
        loop=None,
        **kwargs,
    ):
        self.headers = {}

        super().__init__(
            host=host,
            port=port,
            use_ssl=use_ssl,
            headers=headers,
            http_compress=http_compress,
            opaque_id=opaque_id,
            **kwargs,
        )

        # if providing an SSL context, raise error if any other SSL related flag is used
        if ssl_context and (
            (verify_certs is not DEFAULT)
            or (ssl_show_warn is not DEFAULT)
            or ca_certs
            or client_cert
            or client_key
            or ssl_version
        ):
            warnings.warn(
                "When using `ssl_context`, all other SSL related kwargs are ignored"
            )

        self.ssl_assert_fingerprint = ssl_assert_fingerprint
        if self.use_ssl and ssl_context is None:
            if ssl_version is None:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.SSLContext(ssl_version)

            # Convert all sentinel values to their actual default
            # values if not using an SSLContext.
            if verify_certs is DEFAULT:
                verify_certs = True
            if ssl_show_warn is DEFAULT:
                ssl_show_warn = True

            if verify_certs:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.check_hostname = True
            else:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            ca_certs = DEFAULT_CA_CERTS if ca_certs is None else ca_certs
            if verify_certs:
                if not ca_certs:
                    raise ValueError(
                        "Root certificates are missing for certificate "
                        "validation. Either pass them in using the ca_certs parameter or "
                        "install certifi to use it automatically."
                    )
            else:
                if ssl_show_warn:
                    warnings.warn(
                        f"Connecting to {self.base_url!r} using SSL with verify_certs=False is insecure",
                        stacklevel=2,
                        category=SecurityWarning,
                    )

            if os.path.isfile(ca_certs):
                ssl_context.load_verify_locations(cafile=ca_certs)
            elif os.path.isdir(ca_certs):
                ssl_context.load_verify_locations(capath=ca_certs)
            else:
                raise ValueError("ca_certs parameter is not a path")

            # Use client_cert and client_key variables for SSL certificate configuration.
            if client_cert and not os.path.isfile(client_cert):
                raise ValueError("client_cert is not a path to a file")
            if client_key and not os.path.isfile(client_key):
                raise ValueError("client_key is not a path to a file")
            if client_cert and client_key:
                ssl_context.load_cert_chain(client_cert, client_key)
            elif client_cert:
                ssl_context.load_cert_chain(client_cert)

        self.headers.setdefault("connection", "keep-alive")
        self.loop = loop
        self.session = None

        # Parameters for creating an aiohttp.ClientSession later.
        self._limit = connections_per_node
        self._ssl_context = ssl_context

    async def perform_request(
        self,
        method,
        target,
        body=None,
        request_timeout=None,
        ignore_status=(),
        headers=None,
    ) -> Tuple[HttpResponse, bytes]:
        if self.session is None:
            self._create_aiohttp_session()
        assert self.session is not None

        target = self.url_prefix + target
        url = self.base_url + target

        # There is a bug in aiohttp that disables the re-use
        # of the connection in the pool when method=HEAD.
        # See: aio-libs/aiohttp#1769
        is_head = False
        if method == "HEAD":
            method = "GET"
            is_head = True

        request_timeout = (
            request_timeout if request_timeout is not None else self.request_timeout
        )
        aiohttp_timeout = aiohttp.ClientTimeout(
            total=request_timeout if request_timeout is not None else 0
        )

        request_headers = normalize_headers(self.headers)
        if headers:
            request_headers.update(normalize_headers(headers))

        if self.http_compress and body:
            body = self._gzip_compress(body)
            request_headers["content-encoding"] = "gzip"

        start = self.loop.time()
        try:
            kwargs = {}
            if self.ssl_assert_fingerprint:
                kwargs["ssl"] = aiohttp_fingerprint(self.ssl_assert_fingerprint)

            async with self.session.request(
                method,
                url,
                data=body,
                headers=request_headers,
                timeout=aiohttp_timeout,
                **kwargs,
            ) as response:
                if is_head:  # We actually called 'GET' so throw away the data.
                    await response.release()
                    raw_data = b""
                else:
                    raw_data = await response.read()
                duration = self.loop.time() - start

        # We want to reraise a cancellation or recursion error.
        except RERAISE_EXCEPTIONS:
            raise
        except Exception as e:
            if isinstance(
                e, (asyncio.TimeoutError, aiohttp_exceptions.ServerTimeoutError)
            ):
                raise ConnectionTimeout(
                    "Connection timed out during request", errors=(e,)
                )
            elif isinstance(e, (ssl.SSLError, aiohttp_exceptions.ClientSSLError)):
                raise TlsError(str(e), errors=(e,))
            raise ConnectionError(str(e), errors=(e,))

        return (
            HttpResponse(
                duration=duration,
                version="1.1",
                status=response.status,
                headers=HttpHeaders(response.headers),
            ),
            raw_data,
        )

    def _create_aiohttp_session(self):
        """Creates an aiohttp.ClientSession(). This is delayed until
        the first call to perform_request() so that AsyncTransport has
        a chance to set AiohttpHttpNode.loop
        """
        if self.loop is None:
            self.loop = get_running_loop()
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            skip_auto_headers=("accept", "accept-encoding", "user-agent"),
            auto_decompress=True,
            loop=self.loop,
            cookie_jar=aiohttp.DummyCookieJar(),
            connector=aiohttp.TCPConnector(
                limit=self._limit, use_dns_cache=True, ssl=self._ssl_context
            ),
        )


@functools.lru_cache(maxsize=64, typed=True)
def aiohttp_fingerprint(ssl_assert_fingerprint: str) -> aiohttp.Fingerprint:
    """Changes 'ssl_assert_fingerprint' into a configured 'aiohttp.Fingerprint' instance.
    Uses a cache to prevent creating tons of objects needlessly.
    """
    return aiohttp.Fingerprint(
        base64.b16decode(ssl_assert_fingerprint.replace(":", ""), casefold=True)
    )
