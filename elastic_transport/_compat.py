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
import sys
from urllib.parse import quote as _quote
from urllib.parse import urlencode, urlparse

string_types = (str, bytes)

if sys.version_info >= (3, 7):  # dict is insert ordered on Python 3.7+
    ordered_dict = dict
else:
    from collections import OrderedDict as ordered_dict

try:
    from typing import Mapping, MutableMapping
except ImportError:
    from collections import Mapping, MutableMapping

try:
    from asyncio import get_running_loop
except ImportError:

    def get_running_loop():
        loop = asyncio.get_event_loop()
        if not loop.is_running():
            raise RuntimeError("no running event loop")
        return loop


_QUOTE_ALWAYS_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"
)


def quote(string, safe="/"):
    # type: (str, str) -> str
    # Redefines 'urllib.parse.quote()' to always have the '~' character
    # within the 'ALWAYS_SAFE' list. The character was added in Python 3.7
    safe = "".join(_QUOTE_ALWAYS_SAFE.union(set(safe)))
    return _quote(string, safe)


try:
    from threading import Lock
except ImportError:

    class Lock:
        def __enter__(self) -> None:
            pass

        def __exit__(self, *_) -> None:
            pass


__all__ = [
    "get_running_loop",
    "ordered_dict",
    "quote",
    "urlparse",
    "urlencode",
    "string_types",
    "Mapping",
    "MutableMapping",
    "Lock",
]
