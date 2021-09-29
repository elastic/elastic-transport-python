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

import ssl
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Union

from ._compat import Mapping, MutableMapping

if sys.version_info >= (3, 7):  # dict is insert ordered on Python 3.7+
    ordered_dict = dict
else:
    from collections import OrderedDict as ordered_dict


class QueryParams:
    """Class which handles duplicate keys and ordered parameters for query"""

    __slots__ = ("_internal",)

    def __init__(self, initial=None):
        self._internal = ordered_dict()  # dict[str, list[Any]]

        if initial is not None:
            if isinstance(initial, (dict, QueryParams)):
                initial_items = initial.items()
            elif isinstance(initial, (list, tuple)):
                initial_items = initial
            else:
                raise TypeError(
                    "'params' must be of type Dict[str, Any] or Sequence[Tuple[str, Any]]"
                )
            for key, val in initial_items:
                self.add(key, val)

    def copy(self):
        params = QueryParams()
        for key, val in self.items():
            params.add(key, val)
        return params

    def pop(self, key, default=()):
        self._check_types(key)
        return list(self._internal.pop(key, default))

    def add(self, key, value):
        self._check_types(key)
        self._internal.setdefault(key, []).append(value)

    def extend(self, params):
        for key, val in QueryParams(params).items():
            self.add(key, val)

    def keys(self):
        return self._internal.keys()

    def items(self):
        for key, values in self._internal.items():
            for value in values:
                yield key, value

    def _check_types(self, key):
        if not isinstance(key, str):
            raise TypeError(
                f"Keys in 'params' must be type str not {type(key).__name__}"
            )

    def __setitem__(self, key, value):
        self._check_types(key)
        self._internal.pop(key, None)
        self.add(key, value)

    def __delitem__(self, key):
        self._check_types(key)
        del self._internal[key]

    def __len__(self):
        return sum(map(len, self._internal.values()))

    def __bool__(self):
        return len(self) > 0

    def __eq__(self, other):
        if isinstance(other, QueryParams):
            return list(self.items()) == list(other.items())
        elif isinstance(other, (list, tuple)):
            return self == QueryParams(other)
        elif isinstance(other, dict):
            # Because dicts aren't ordered we don't compare
            # order when comparing to a dict
            return sorted(self.items()) == sorted(QueryParams(other).items())
        return NotImplemented

    def __ne__(self, other):
        if not isinstance(other, (QueryParams, list, tuple, dict)):
            return NotImplemented
        return not (self == other)

    def __contains__(self, item):
        return item in self._internal

    def __repr__(self):
        return f"QueryParams({list(self.items())!r})"

    __str__ = __repr__


class HttpHeaders(MutableMapping[str, str]):
    """HTTP headers"""

    def __init__(self, initial=None):
        self._internal = {}
        self._frozen = False
        if initial:
            for key, val in dict(initial).items():
                self._internal[self._normalize_key(key)] = (key, val)

    def __setitem__(self, key, value):
        if self._frozen:
            raise ValueError("Can't modify headers that have been frozen")
        self._internal[self._normalize_key(key)] = (key, value)

    def __getitem__(self, item):
        return self._internal[self._normalize_key(item)][1]

    def __delitem__(self, key):
        if self._frozen:
            raise ValueError("Can't modify headers that have been frozen")
        del self._internal[self._normalize_key(key)]

    def __eq__(self, other):
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Mapping):
            return dict(self.items()) != dict(other.items())
        return NotImplemented

    def __iter__(self):
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._internal)

    def __bool__(self) -> bool:
        return bool(self._internal)

    def __contains__(self, item: str) -> bool:
        return self._normalize_key(item) in self._internal

    def __repr__(self) -> str:
        return repr(dict(self.items()))

    def __str__(self) -> str:
        return str(dict(self.items()))

    def __hash__(self) -> int:
        if not self._frozen:
            raise ValueError("Can't calculate the hash of headers that aren't frozen")
        return hash(tuple((k, v) for k, (_, v) in sorted(self._internal.items())))

    def get(self, key, default=None):
        return self._internal.get(self._normalize_key(key), (None, default))[1]

    def keys(self):
        return [key for _, (key, _) in self._internal.items()]

    def values(self):
        return [val for _, (_, val) in self._internal.items()]

    def items(self):
        return [(key, val) for _, (key, val) in self._internal.items()]

    def freeze(self) -> "HttpHeaders":
        """Freezes the current set of headers so they can be used in hashes.
        Returns the same instance, doesn't make a copy.
        """
        self._frozen = True
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    def copy(self) -> "HttpHeaders":
        return HttpHeaders(self.items())

    def _normalize_key(self, key: str) -> str:
        return key.lower() if hasattr(key, "lower") else key


@dataclass
class ApiResponseMeta:
    """Metadata that is returned from Transport.perform_request()"""

    #: Node which handled the request
    node: "NodeConfig"

    #: Number of seconds from start of request to start of response
    duration: float

    #: HTTP version being used
    http_version: str

    #: HTTP status code
    status: int

    #: HTTP headers
    headers: HttpHeaders

    #: Extras that can be set to anything, typically used by third-parties.
    #: Third-party keys should start with an underscore and prefix.
    _extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def mimetype(self) -> Optional[str]:
        """Mimetype to be used by the serializer to decode the raw response bytes."""
        try:
            content_type = self.headers["content-type"]
            return content_type.partition(";")[0] or None
        except KeyError:
            return None


def _empty_frozen_http_headers() -> HttpHeaders:
    """Used for the 'default_factory' of the 'NodeConfig.headers'"""
    return HttpHeaders().freeze()


@dataclass(repr=True)
class NodeConfig:
    """Configuration options available for every node."""

    #: Protocol in use to connect to the node
    scheme: str
    #: IP address or hostname to connect to
    host: str
    #: IP port to connect to
    port: int
    #: Prefix to add to the path of every request
    path_prefix: str = ""

    #: Default HTTP headers to add to every request
    headers: Union[HttpHeaders, Mapping[str, str]] = field(
        default_factory=_empty_frozen_http_headers
    )

    #: Number of concurrent connections that are
    #: able to be open at one time for this node.
    #: Having multiple connections per node allows
    #: for higher concurrency of requests.
    connections_per_node: int = 10

    #: Number of seconds to wait before a request should timeout.
    request_timeout: Optional[int] = 10

    #: Set to ``True`` to enable HTTP compression
    #: of request and response bodies via gzip.
    http_compress: Optional[bool] = False

    #: Set to ``True`` to verify the node's TLS certificate against 'ca_certs'
    #: Setting to ``False`` will disable verifying the node's certificate.
    verify_certs: Optional[bool] = True

    #: Path to a CA bundle or directory containing bundles. By default
    #: If the ``certifi`` package is installed and ``verify_certs`` is
    #: set to ``True`` this value will be set to ``certifi.where()``.
    ca_certs: Optional[str] = None

    #: Path to a client certificate for TLS client authentication.
    client_cert: Optional[str] = None
    #: Path to a client private key for TLS client authentication.
    client_key: Optional[str] = None
    #: Hostname or IP address to verify on the node's certificate.
    #: This is useful if the certificate contains a different value
    #: than the one supplied in ``host``. An example of this situation
    #: is connecting to an IP address instead of a hostname.
    #: Set to ``False`` to disable certificate hostname verification.
    ssl_assert_hostname: Optional[str] = None
    #: SHA-256 fingerprint of the node's certificate. If this value is
    #: given then root-of-trust verification isn't done and only the
    #: node's certificate fingerprint is verified.
    ssl_assert_fingerprint: Optional[str] = None
    #: Minimum TLS version to use to connect to the node.
    ssl_version: Optional[int] = None
    #: Pre-configured :class:`ssl.SSLContext` object. If this value
    #: is given then no other TLS options (besides ``ssl_assert_fingerprint``)
    #: can be set on the :class:`elastic_transport.NodeConfig`.
    ssl_context: Optional[ssl.SSLContext] = field(default=None, hash=False)
    #: Set to ``False`` to disable the :class:`elastic_transport.SecurityWarning`
    #: issued when using ``verify_certs=False``.
    ssl_show_warn: bool = True

    # Extras that can be set to anything, typically used
    # for annotating this node with additional information for
    # future decisions like sniffing, instance roles, etc.
    # Third-party keys should start with an underscore and prefix.
    _extras: Dict[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if not isinstance(self.headers, HttpHeaders) or not self.headers.frozen:
            self.headers = HttpHeaders(self.headers).freeze()

        if self.scheme != self.scheme.lower():
            raise ValueError("'scheme' must be lowercase")
        if "[" in self.host or "]" in self.host:
            raise ValueError("'host' must not have square braces")
        if self.port < 0:
            raise ValueError("'port' must be a positive integer")
        if self.connections_per_node <= 0:
            raise ValueError("'connections_per_node' must be a positive integer")
        if self.path_prefix:
            self.path_prefix = (
                ("/" + self.path_prefix.strip("/")) if self.path_prefix else ""
            )

        tls_options = [
            "ca_certs",
            "client_cert",
            "client_key",
            "ssl_assert_hostname",
            "ssl_assert_fingerprint",
            "ssl_context",
        ]

        # Disallow setting TLS options on non-HTTPS connections.
        if self.scheme != "https":
            if any(getattr(self, attr) is not None for attr in tls_options):
                raise ValueError("TLS options require scheme to be 'https'")

        elif self.scheme == "https":
            # It's not valid to set 'ssl_context' and any other
            # TLS option, the SSLContext object must be configured
            # the way the user wants already.
            if self.ssl_context is not None and any(
                filter(
                    lambda attr: (
                        attr not in ("ssl_context", "ssl_assert_fingerprint")
                        and getattr(self, attr) is not None
                    ),
                    tls_options,
                )
            ):
                raise ValueError(
                    "The 'ssl_context' option can't be combined with other TLS options"
                )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NodeConfig):
            return NotImplemented
        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.port == other.port
            and self.path_prefix == other.path_prefix
        )

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, NodeConfig):
            return NotImplemented
        return not self == other

    def __hash__(self) -> int:
        return hash(
            (
                self.scheme,
                self.host,
                self.port,
                self.path_prefix,
            )
        )


@dataclass(frozen=True, repr=True)
class RequestOptions:
    """Options which can be passed per request to the Transport"""

    headers: HttpHeaders = field(default_factory=_empty_frozen_http_headers())
    timeout: Optional[float] = 5.0
    max_retries: int = 0
    retry_on_status: FrozenSet[int] = frozenset((429, 501, 502, 503))
    retry_on_timeout: bool = True
    ignore_status: FrozenSet[int] = frozenset()

    # Third-party extras for custom implementations or smuggling data
    # to the connection/transport layer. Third-party keys should start
    # with an underscore and prefix.
    _extras: Dict[str, Any] = field(default_factory=dict, hash=False)
