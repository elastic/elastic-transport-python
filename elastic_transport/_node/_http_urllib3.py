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
import threading
import time
import warnings
from typing import Any, Dict, Optional, Union

try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata  # type: ignore[no-redef, import-not-found]

import urllib3
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError, ReadTimeoutError
from urllib3.util.retry import Retry

from .._compat import warn_stacklevel
from .._exceptions import ConnectionError, ConnectionTimeout, SecurityWarning, TlsError
from .._models import ApiResponseMeta, HttpHeaders, NodeConfig
from ..client_utils import DEFAULT, DefaultType, client_meta_version
from ._base import (
    BUILTIN_EXCEPTIONS,
    DEFAULT_CA_CERTS,
    RERAISE_EXCEPTIONS,
    BaseNode,
    NodeApiResponse,
    ssl_context_from_node_config,
)
from ._ca_fingerprint import (
    apply_assert_hostname,
    fetch_pinned_ssl_context,
    validate_fingerprint_options,
)


class Urllib3HttpNode(BaseNode):
    """Default synchronous node class using the ``urllib3`` library via HTTP"""

    _CLIENT_META_HTTP_CLIENT = ("ur", client_meta_version(metadata.version("urllib3")))

    def __init__(self, config: NodeConfig):
        super().__init__(config)

        pool_class: type[urllib3.HTTPConnectionPool] = urllib3.HTTPConnectionPool
        kw: Dict[str, Any] = {}

        if config.scheme == "https":
            pool_class = urllib3.HTTPSConnectionPool
            if config.ssl_assert_fingerprint is not None:
                # Probe on the first request. Construction stays offline if the node is down.
                validate_fingerprint_options(config)
            else:
                ssl_context = ssl_context_from_node_config(config)
                kw["ssl_context"] = ssl_context
                kw["assert_hostname"] = config.ssl_assert_hostname

                # Convert all sentinel values to their actual default
                # values if not using an SSLContext.
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

                    kw.update(
                        {
                            "cert_reqs": "CERT_REQUIRED",
                            "ca_certs": ca_certs,
                            "cert_file": config.client_cert,
                            "key_file": config.client_key,
                        }
                    )
                else:
                    kw["cert_reqs"] = "CERT_NONE"

                    if config.ssl_show_warn:
                        warnings.warn(
                            f"Connecting to {self.base_url!r} using TLS with verify_certs=False is insecure",
                            stacklevel=warn_stacklevel(),
                            category=SecurityWarning,
                        )
                    else:
                        urllib3.disable_warnings()

        self._pool_class = pool_class
        self._pool_kw = kw
        self._pin_lock = threading.Lock()
        self.pool: Optional[urllib3.HTTPConnectionPool] = None
        if config.ssl_assert_fingerprint is None:
            self.pool = self._open_pool()

    def perform_request(
        self,
        method: str,
        target: str,
        body: Optional[bytes] = None,
        headers: Optional[HttpHeaders] = None,
        request_timeout: Union[DefaultType, Optional[float]] = DEFAULT,
    ) -> NodeApiResponse:
        if self.path_prefix:
            target = f"{self.path_prefix}{target}"

        start = time.time()
        try:
            kw = {}
            if request_timeout is not DEFAULT:
                kw["timeout"] = request_timeout

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

            # After the headers exist, so a failed probe can be logged.
            self._ensure_pinned(
                self.config.request_timeout
                if request_timeout is DEFAULT
                else request_timeout
            )
            assert self.pool is not None
            response = self.pool.urlopen(
                method,
                target,
                body=body_to_send,
                retries=Retry(False),
                headers=request_headers,
                **kw,  # type: ignore[arg-type]
            )
            response_headers = HttpHeaders(response.headers)
            data = response.data
            duration = time.time() - start

        except RERAISE_EXCEPTIONS:
            raise
        except Exception as e:
            err: Exception
            if isinstance(e, NewConnectionError):
                err = ConnectionError(str(e), errors=(e,))
            elif isinstance(e, (ConnectTimeoutError, ReadTimeoutError, TimeoutError)):
                err = ConnectionTimeout(
                    "Connection timed out during request", errors=(e,)
                )
            elif isinstance(e, (ssl.SSLError, urllib3.exceptions.SSLError)):
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
            raise err from e

        meta = ApiResponseMeta(
            node=self.config,
            duration=duration,
            http_version="1.1",
            status=response.status,
            headers=response_headers,
        )
        self._log_request(
            method=method,
            target=target,
            headers=request_headers,
            body=body,
            meta=meta,
            response=data,
        )
        return NodeApiResponse(
            meta,
            data,
        )

    def close(self) -> None:
        """
        Explicitly closes connection
        """
        if self.pool is not None:
            self.pool.close()

    def _open_pool(self, **extra: Any) -> urllib3.HTTPConnectionPool:
        kw = dict(self._pool_kw)
        kw.update(extra)
        return self._pool_class(
            self.config.host,
            port=self.config.port,
            timeout=urllib3.Timeout(total=self.config.request_timeout),
            maxsize=self.config.connections_per_node,
            block=True,
            **kw,
        )

    def _ensure_pinned(self, timeout: Optional[float]) -> None:
        if self.pool is not None:
            return
        with self._pin_lock:
            if self.pool is not None:
                return
            ctx = fetch_pinned_ssl_context(self.config, timeout)
            extra: Dict[str, Any] = {"ssl_context": ctx}
            apply_assert_hostname(extra, self.config)
            self.pool = self._open_pool(**extra)
