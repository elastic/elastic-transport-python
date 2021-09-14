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

import sys
from dataclasses import dataclass
from typing import Optional

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
        if initial:
            for key, val in dict(initial).items():
                self._internal[self._normalize_key(key)] = (key, val)

    def __setitem__(self, key, value):
        self._internal[self._normalize_key(key)] = (key, value)

    def __getitem__(self, item):
        return self._internal[self._normalize_key(item)][1]

    def __delitem__(self, key):
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

    def __len__(self):
        return len(self._internal)

    def __bool__(self):
        return bool(self._internal)

    def __contains__(self, item):
        return self._normalize_key(item) in self._internal

    def __repr__(self):
        return repr(dict(self.items()))

    def __str__(self):
        return str(dict(self.items()))

    def get(self, key, default=None):
        return self._internal.get(self._normalize_key(key), (None, default))[1]

    def keys(self):
        return [key for _, (key, _) in self._internal.items()]

    def values(self):
        return [val for _, (_, val) in self._internal.items()]

    def items(self):
        return [(key, val) for _, (key, val) in self._internal.items()]

    def copy(self):
        return HttpHeaders(self.items())

    def _normalize_key(self, key):
        return key.lower() if hasattr(key, "lower") else key


@dataclass
class HttpResponse:
    """Response from BaseNode.perform_request()"""

    #: Number of seconds from start of request to start of response
    duration: float

    #: HTTP version being used
    version: str

    #: HTTP status code
    status: int

    #: HTTP headers
    headers: HttpHeaders

    @property
    def mimetype(self) -> Optional[str]:
        """Mimetype to be used by the serializer to decode the raw response bytes"""
        try:
            content_type = self.headers["content-type"]
            return content_type.partition(";")[0] or None
        except KeyError:
            return None
