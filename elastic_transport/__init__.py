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

"""Transport classes and utilities shared among Python Elastic client libraries"""

from ._async_transport import AsyncTransport
from ._exceptions import (
    ApiError,
    ConnectionError,
    ConnectionTimeout,
    SecurityWarning,
    SerializationError,
    TlsError,
    TransportError,
    TransportWarning,
)
from ._models import ApiResponseMeta, HttpHeaders, NodeConfig, SniffOptions
from ._node import (
    AiohttpHttpNode,
    BaseAsyncNode,
    BaseNode,
    RequestsHttpNode,
    Urllib3HttpNode,
)
from ._node_pool import NodePool, NodeSelector, RandomSelector, RoundRobinSelector
from ._serializer import (
    JsonSerializer,
    NdjsonSerializer,
    Serializer,
    SerializerCollection,
    TextSerializer,
)
from ._transport import Transport
from ._version import __version__ as __version__  # noqa

__all__ = [
    "AiohttpHttpNode",
    "ApiError",
    "ApiResponseMeta",
    "AsyncTransport",
    "BaseAsyncNode",
    "BaseNode",
    "ConnectionError",
    "ConnectionTimeout",
    "HttpHeaders",
    "JsonSerializer",
    "NdjsonSerializer",
    "NodeConfig",
    "NodePool",
    "NodeSelector",
    "RandomSelector",
    "RequestsHttpNode",
    "RoundRobinSelector",
    "SecurityWarning",
    "SerializationError",
    "Serializer",
    "SerializerCollection",
    "SniffOptions",
    "TextSerializer",
    "TlsError",
    "Transport",
    "TransportError",
    "TransportWarning",
    "Urllib3HttpNode",
]
