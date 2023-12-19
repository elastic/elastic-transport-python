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
import time
import warnings
from typing import Optional, Tuple, Union

from .._exceptions import ConnectionError, ConnectionTimeout
from .._models import ApiResponseMeta, HttpHeaders, NodeConfig
from ..client_utils import DEFAULT, DefaultType, client_meta_version
from ._base import (
    BUILTIN_EXCEPTIONS,
    RERAISE_EXCEPTIONS,
    NodeApiResponse,
    ssl_context_from_node_config,
)
from ._base_async import BaseAsyncNode

try:
    import httpx

    _HTTPX_AVAILABLE = True
    _HTTPX_META_VERSION = client_meta_version(httpx.__version__)
except ImportError:
    _HTTPX_AVAILABLE = False
    _HTTPX_META_VERSION = ""


# https://github.com/encode/httpx/blob/b4b27ff6777c8906c2b31dd879bd4cc1d9e4f6ce/httpx/_types.py#L67-L75
CertTypes = Union[
    # certfile
    str,
    # (certfile, keyfile)
    Tuple[str, Optional[str]],
    # (certfile, keyfile, password)
    Tuple[str, Optional[str], Optional[str]],
]
VerifyTypes = Union[str, bool, ssl.SSLContext]


class HttpxAsyncNode(BaseAsyncNode):
    def __init__(self, config: NodeConfig):
        if not _HTTPX_AVAILABLE:  # pragma: nocover
            raise ValueError("You must have 'httpx' installed to use HttpxNode")
        super().__init__(config)

        verify: VerifyTypes = False
        if config.scheme == "https":
            if config.ssl_context is not None:
                verify = ssl_context_from_node_config(config)
            else:
                if config.ca_certs is not None:
                    if not config.verify_certs:
                        raise ValueError(
                            "You cannot use 'ca_certs' when 'verify_certs=False'"
                        )
                    verify = config.ca_certs
                elif config.verify_certs is not None:
                    verify = config.verify_certs

                if not config.verify_certs and config.ssl_show_warn:
                    warnings.warn(
                        f"Connecting to {self.base_url!r} using TLS with verify_certs=False is insecure"
                    )

        cert: Optional[CertTypes] = None
        if config.client_cert:
            if config.client_key:
                cert = (config.client_cert, config.client_key)
            else:
                cert = config.client_cert

        self.client = httpx.AsyncClient(
            base_url=f"{config.scheme}://{config.host}:{config.port}",
            limits=httpx.Limits(max_connections=config.connections_per_node),
            verify=verify,
            cert=cert,
            timeout=config.request_timeout,
        )

    async def perform_request(  # type: ignore[override]
        self,
        method: str,
        target: str,
        body: bytes | None = None,
        headers: HttpHeaders | None = None,
        request_timeout: DefaultType | (float | None) = DEFAULT,
    ) -> NodeApiResponse:
        resolved_headers = self._headers.copy()
        if headers:
            resolved_headers.update(headers)

        if body:
            if self._http_compress:
                resolved_body = gzip.compress(body)
                resolved_headers["content-encoding"] = "gzip"
            else:
                resolved_body = body
        else:
            resolved_body = None

        try:
            start = time.perf_counter()
            if request_timeout is DEFAULT:
                resp = await self.client.request(
                    method,
                    target,
                    content=resolved_body,
                    headers=dict(resolved_headers),
                )
            else:
                resp = await self.client.request(
                    method,
                    target,
                    content=resolved_body,
                    headers=dict(resolved_headers),
                    timeout=request_timeout,
                )
            resp.raise_for_status()
            response_body = resp.read()
            duration = time.perf_counter() - start
        except RERAISE_EXCEPTIONS + BUILTIN_EXCEPTIONS:
            raise
        except Exception as exc:
            resolved_exc: Exception
            if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
                resolved_exc = ConnectionTimeout(
                    "Connection timed out during request", errors=(exc,)
                )
            else:
                resolved_exc = ConnectionError(str(exc), errors=(exc,))
            self._log_request(
                method=method,
                target=target,
                headers=resolved_headers,
                body=body,
                exception=resolved_exc,
            )
            raise resolved_exc from None

        meta = ApiResponseMeta(
            resp.status_code,
            resp.http_version,
            HttpHeaders(resp.headers),
            duration,
            self.config,
        )

        self._log_request(
            method=method,
            target=target,
            headers=resolved_headers,
            body=body,
            meta=meta,
            response=response_body,
        )

        return NodeApiResponse(meta, response_body)

    async def close(self) -> None:  # type: ignore[override]
        await self.client.aclose()
