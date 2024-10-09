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
import gzip
import os
import re
import ssl
import warnings
from typing import Optional, Union

from .._compat import warn_stacklevel
from .._exceptions import ConnectionError, ConnectionTimeout, SecurityWarning, TlsError
from .._models import ApiResponseMeta, HttpHeaders, NodeConfig
from ..client_utils import DefaultType, client_meta_version
from ._base import (
    BUILTIN_EXCEPTIONS,
    DEFAULT_CA_CERTS,
    RERAISE_EXCEPTIONS,
    NodeApiResponse,
    ssl_context_from_node_config,
)
from ._base_async import BaseAsyncNode

try:
    import aiosonic  # type: ignore
    from aiosonic.connection import TCPConnector  # type: ignore
    from aiosonic.exceptions import TimeoutException  # type: ignore
    from aiosonic.resolver import get_loop  # type: ignore
    from aiosonic.timeout import Timeouts  # type: ignore
    from aiosonic.version import VERSION  # type: ignore

    _AIOSONIC_AVAILABLE = True
    _AIOSONIC_META_VERSION = client_meta_version(VERSION)

    _version_parts = []
    for _version_part in VERSION.split(".")[:3]:
        try:
            _version_parts.append(int(re.search(r"^([0-9]+)", _version_part).group(1)))  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            break

except ImportError:  # pragma: nocover
    _AIOSONIC_AVAILABLE = False
    _AIOSONIC_META_VERSION = ""


class AiosonicHttpNode(BaseAsyncNode):
    """Default asynchronous node class using the ``aiosonic`` library via HTTP"""

    _CLIENT_META_HTTP_CLIENT = ("as", _AIOSONIC_META_VERSION)
    _BIG_TIMEOUT = 60 * 2  # 2 min timeout

    def __init__(self, config: NodeConfig):
        if not _AIOSONIC_AVAILABLE:  # pragma: nocover
            raise ValueError(
                "You must have 'aiosonic' installed to use AiosonicHttpNode"
            )

        super().__init__(config)

        ssl_context: Optional[ssl.SSLContext] = None
        if config.scheme == "https":
            if config.ssl_context is not None:
                ssl_context = ssl_context_from_node_config(config)
            else:
                ssl_context = ssl_context_from_node_config(config)

                ca_certs = (
                    DEFAULT_CA_CERTS if config.ca_certs is None else config.ca_certs
                )
                if config.verify_certs:
                    if not ca_certs:
                        raise ValueError(
                            "Root certificates are missing for certificate "
                            "validation. Either pass them in using the ca_certs parameter or "
                            "install certifi to use it automatically."
                        )
                else:
                    if config.ssl_show_warn:
                        warnings.warn(
                            f"Connecting to {self.base_url!r} using TLS with verify_certs=False is insecure",
                            stacklevel=warn_stacklevel(),
                            category=SecurityWarning,
                        )

                if ca_certs is not None:
                    if os.path.isfile(ca_certs):
                        ssl_context.load_verify_locations(cafile=ca_certs)
                    elif os.path.isdir(ca_certs):
                        ssl_context.load_verify_locations(capath=ca_certs)
                    else:
                        raise ValueError("ca_certs parameter is not a path")

                # Use client_cert and client_key variables for SSL certificate configuration.
                if config.client_cert and not os.path.isfile(config.client_cert):
                    raise ValueError("client_cert is not a path to a file")
                if config.client_key and not os.path.isfile(config.client_key):
                    raise ValueError("client_key is not a path to a file")
                if config.client_cert and config.client_key:
                    ssl_context.load_cert_chain(config.client_cert, config.client_key)
                elif config.client_cert:
                    ssl_context.load_cert_chain(config.client_cert)

        self._loop: asyncio.AbstractEventLoop = None  # type: ignore[assignment]
        if _AIOSONIC_AVAILABLE:
            self.client = aiosonic.HTTPClient(
                connector=TCPConnector(
                    pool_size=config.connections_per_node,
                    use_dns_cache=True,
                ),
            )

        self._ssl_context = ssl_context

    async def perform_request(  # type: ignore[override]
        self,
        method: str,
        target: str,
        body: Optional[bytes] = None,
        headers: Optional[HttpHeaders] = None,
        request_timeout: Union[DefaultType, Optional[float]] = None,
    ) -> NodeApiResponse:
        url = self.base_url + target

        if not self._loop:
            self._loop = get_loop()

        timeouts = Timeouts(
            request_timeout=(request_timeout if request_timeout else self._BIG_TIMEOUT)
        )

        request_headers = self._headers.copy()
        if headers:
            request_headers.update(headers)

        body_to_send: Optional[bytes]
        if body:
            if self._http_compress:
                body_to_send = gzip.compress(body)
                request_headers["content-encoding"] = "gzip"
            else:
                body_to_send = body
        else:
            body_to_send = None

        try:
            start = self._loop.time()
            response = await self.client.request(
                method=method,
                url=url,
                data=body_to_send,
                headers=request_headers,
                timeouts=timeouts,
                ssl=self._ssl_context or None,
            )
            raw_data = await response.content()
            duration = self._loop.time() - start

        # We want to reraise a cancellation or recursion error.
        except RERAISE_EXCEPTIONS:
            raise
        except Exception as e:
            err: Exception
            if isinstance(e, (asyncio.TimeoutError, TimeoutException)):
                err = ConnectionTimeout(
                    "Connection timed out during request", errors=(e,)
                )
            elif isinstance(e, (ssl.SSLError)):
                err = TlsError(str(e), errors=(e,))
            elif isinstance(e, BUILTIN_EXCEPTIONS):
                raise
            else:
                err = ConnectionError(str(e), errors=(e,))
            self._log_request(
                method=method,
                target=target,
                headers=request_headers,
                body=body,
                exception=err,
            )
            raise err from None

        meta = ApiResponseMeta(
            node=self.config,
            duration=duration,
            http_version="1.1",
            status=response.status_code,
            headers=HttpHeaders(response.headers),
        )
        self._log_request(
            method=method,
            target=target,
            headers=request_headers,
            body=body,
            meta=meta,
            response=raw_data,
        )
        return NodeApiResponse(
            meta,
            raw_data,
        )
