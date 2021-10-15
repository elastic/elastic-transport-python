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
from typing import Any, Dict, Optional, Tuple, Union

import urllib3  # type: ignore[import]
from urllib3.exceptions import (  # type: ignore[import]
    ConnectTimeoutError,
    ReadTimeoutError,
)
from urllib3.util.retry import Retry  # type: ignore[import]

from .._compat import warn_stacklevel
from .._exceptions import ConnectionError, ConnectionTimeout, SecurityWarning, TlsError
from .._models import ApiResponseMeta, HttpHeaders, NodeConfig
from ..client_utils import DEFAULT, DefaultType, client_meta_version
from ._base import DEFAULT_CA_CERTS, RERAISE_EXCEPTIONS, BaseNode

try:
    from ._urllib3_chain_certs import HTTPSConnectionPool
except (ImportError, AttributeError):
    HTTPSConnectionPool = urllib3.HTTPSConnectionPool  # type: ignore[misc]


class Urllib3HttpNode(BaseNode):
    """Default synchronous node class using the ``urllib3`` library via HTTP"""

    _CLIENT_META_HTTP_CLIENT = ("ur", client_meta_version(urllib3.__version__))

    def __init__(self, config: NodeConfig):
        super().__init__(config)

        pool_class = urllib3.HTTPConnectionPool
        kw: Dict[str, Any] = {}

        # if ssl_context provided use SSL by default
        if config.scheme == "https" and config.ssl_context:
            pool_class = HTTPSConnectionPool
            kw.update(
                {
                    "assert_fingerprint": config.ssl_assert_fingerprint,
                    "ssl_context": config.ssl_context,
                }
            )

        elif config.scheme == "https":
            pool_class = HTTPSConnectionPool
            kw.update(
                {
                    "ssl_version": config.ssl_version,
                    "assert_hostname": config.ssl_assert_hostname,
                    "assert_fingerprint": config.ssl_assert_fingerprint,
                }
            )

            # Convert all sentinel values to their actual default
            # values if not using an SSLContext.
            ca_certs = DEFAULT_CA_CERTS if config.ca_certs is None else config.ca_certs
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

        self.pool = pool_class(
            config.host,
            port=config.port,
            timeout=urllib3.Timeout(total=config.request_timeout),
            maxsize=config.connections_per_node,
            block=False,
            **kw,
        )

    def perform_request(
        self,
        method: str,
        target: str,
        body: Optional[bytes] = None,
        headers: Optional[HttpHeaders] = None,
        request_timeout: Union[DefaultType, Optional[float]] = DEFAULT,
    ) -> Tuple[ApiResponseMeta, bytes]:

        start = time.time()
        try:
            kw = {}
            if request_timeout is not DEFAULT:
                kw["timeout"] = request_timeout

            request_headers = self._headers.copy()
            if headers:
                request_headers.update(headers)

            if body:
                if self._http_compress:
                    body = gzip.compress(body)
                    request_headers["content-encoding"] = "gzip"
            else:
                body = None

            response = self.pool.urlopen(
                method,
                target,
                body=body,
                retries=Retry(False),
                headers=request_headers,
                **kw,
            )
            response_headers = HttpHeaders(response.headers)
            data = response.data
            duration = time.time() - start

        except RERAISE_EXCEPTIONS:
            raise
        except Exception as e:
            if isinstance(e, (ConnectTimeoutError, ReadTimeoutError)):
                raise ConnectionTimeout(
                    "Connection timed out during request", errors=(e,)
                ) from None
            elif isinstance(e, (ssl.SSLError, urllib3.exceptions.SSLError)):
                raise TlsError(str(e), errors=(e,)) from None
            raise ConnectionError(str(e), errors=(e,)) from None

        return (
            ApiResponseMeta(
                node=self.config,
                duration=duration,
                http_version="1.1",
                status=response.status,
                headers=response_headers,
            ),
            data,
        )

    def close(self) -> None:
        """
        Explicitly closes connection
        """
        self.pool.close()
