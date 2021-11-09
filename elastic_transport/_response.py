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

from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    overload,
)

from ._models import ApiResponseMeta

_RawType = TypeVar("_RawType")
_BodyType = TypeVar("_BodyType")
_ObjectBodyType = TypeVar("_ObjectBodyType")
_ListItemRawType = TypeVar("_ListItemRawType")
_ListItemBodyType = TypeVar("_ListItemBodyType")


class ApiResponse(Generic[_RawType, _BodyType]):
    """Base class for all API response classes"""

    __slots__ = ("_raw", "_meta", "_body_cls")

    def __init__(
        self,
        raw: _RawType,
        meta: ApiResponseMeta,
        body_cls: Optional[Type[_BodyType]] = None,
    ):
        self._raw = raw
        self._meta = meta
        self._body_cls = body_cls

    def __repr__(self) -> str:
        body_repr: Any = self._raw
        try:
            body_repr = self.body
        except NotImplementedError:
            pass
        return f"{type(self).__name__}({body_repr!r})"

    def __contains__(self, item: Any) -> bool:
        return item in self._raw  # type: ignore[operator]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ApiResponse):
            other = other._raw
        return self._raw == other

    def __ne__(self, other: object) -> bool:
        if isinstance(other, ApiResponse):
            other = other.raw
        return self._raw != other

    def __getitem__(self, item: Any) -> Any:
        return self._raw[item]  # type: ignore[index]

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._raw, attr)

    def __len__(self) -> int:
        return len(self._raw)  # type: ignore[arg-type]

    def __iter__(self) -> Iterable[Any]:
        return iter(self._raw)  # type: ignore[no-any-return,call-overload]

    def __str__(self) -> str:
        return str(self._raw)

    def __bool__(self) -> bool:
        return bool(self._raw)

    @property
    def meta(self) -> ApiResponseMeta:
        """Response metadata"""
        return self._meta

    @property
    def raw(self) -> _RawType:
        """Raw deserialized response"""
        return self._raw

    @property
    def body(self) -> _BodyType:
        """User-friendly view into the raw response with type hints if applicable"""
        raise NotImplementedError()


class TextApiResponse(ApiResponse[str, str]):
    """API responses which are text such as 'text/plain' or 'text/csv'"""

    def __init__(self, raw: str, meta: ApiResponseMeta):
        super().__init__(raw=raw, meta=meta)

    def __iter__(self) -> Iterable[str]:
        return iter(self._raw)

    def __getitem__(self, item: Union[int, slice]) -> str:
        return self._raw[item]

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def body(self) -> str:
        return self.raw


class BinaryApiResponse(ApiResponse[bytes, bytes]):
    """API responses which are a binary response such as Mapbox vector tiles"""

    def __init__(self, raw: bytes, meta: ApiResponseMeta):
        super().__init__(raw=raw, meta=meta)

    def __iter__(self) -> Iterable[int]:
        return iter(self.raw)

    @overload
    def __getitem__(self, item: slice) -> bytes:
        ...

    @overload
    def __getitem__(self, item: int) -> int:
        ...

    def __getitem__(self, item: Union[int, slice]) -> Union[int, bytes]:
        return self.raw[item]

    @property
    def raw(self) -> bytes:
        return self._raw

    @property
    def body(self) -> bytes:
        return self.raw


class HeadApiResponse(ApiResponse[bool, bool]):
    """API responses which are for an 'exists' / HEAD API request"""

    def __init__(self, meta: ApiResponseMeta):
        super().__init__(raw=200 <= meta.status < 300, meta=meta)

    def __bool__(self) -> bool:
        return 200 <= self.meta.status < 300

    @property
    def raw(self) -> bool:
        return bool(self)

    @property
    def body(self) -> bool:
        return bool(self)


class ObjectApiResponse(
    Generic[_ObjectBodyType], ApiResponse[Dict[str, Any], _ObjectBodyType]
):
    """API responses which are for a JSON object"""

    def __init__(self, raw: Dict[str, Any], meta: ApiResponseMeta):
        super().__init__(raw=raw, meta=meta)

    def __getitem__(self, item: str) -> Any:
        return self.raw[item]

    def __iter__(self) -> Iterator[str]:
        return iter(self.raw)

    @property
    def raw(self) -> Dict[str, Any]:
        return self._raw

    @property
    def body(self) -> _ObjectBodyType:
        if self._body_cls is None:
            raise NotImplementedError
        return self._body_cls(self.raw)  # type: ignore[call-arg]


class ListApiResponse(
    Generic[_ListItemRawType, _ListItemBodyType],
    ApiResponse[List[_ListItemRawType], List[_ListItemBodyType]],
):
    """API responses which are a list of items. Can be NDJSON or a JSON list"""

    def __init__(self, raw: List[Any], meta: ApiResponseMeta):
        super().__init__(raw=raw, meta=meta)

    @overload
    def __getitem__(self, item: slice) -> List[_ListItemRawType]:
        ...

    @overload
    def __getitem__(self, item: int) -> _ListItemRawType:
        ...

    def __getitem__(
        self, item: Union[int, slice]
    ) -> Union[_ListItemRawType, List[_ListItemRawType]]:
        return self.raw[item]

    def __iter__(self) -> Iterable[_ListItemRawType]:
        return iter(self.raw)

    @property
    def raw(self) -> List[_ListItemRawType]:
        return self._raw

    @property
    def body(self) -> List[_ListItemBodyType]:
        if self._body_cls is None:
            raise NotImplementedError
        return [self._body_cls(item) for item in self._raw]  # type: ignore[call-overload]
