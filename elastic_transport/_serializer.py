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

import json
import uuid
from datetime import date
from decimal import Decimal
from typing import Any, ClassVar, Mapping, Optional

from ._exceptions import SerializationError


class Serializer:
    mimetype: ClassVar[str]

    def loads(self, data: bytes) -> Any:  # pragma: nocover
        raise NotImplementedError()

    def dumps(self, data: Any) -> bytes:  # pragma: nocover
        raise NotImplementedError()


class TextSerializer(Serializer):
    mimetype = "text/*"

    def loads(self, data: bytes) -> str:
        try:
            return data.decode("utf-8", "surrogatepass")
        except UnicodeError:
            raise SerializationError(f"Unable to deserialize as text: {data!r}")

    def dumps(self, data: str) -> bytes:
        try:
            return data.encode("utf-8", "surrogatepass")
        except (AttributeError, UnicodeError, TypeError) as e:
            raise SerializationError(
                f"Unable to serialize to text: {data!r}", errors=(e,)
            )


class JsonSerializer(Serializer):
    mimetype = "application/json"

    def default(self, data: Any) -> Any:
        if isinstance(data, date):
            return data.isoformat()
        elif isinstance(data, uuid.UUID):
            return str(data)
        elif isinstance(data, Decimal):
            return float(data)
        raise SerializationError(
            message=f"Unable to serialize to JSON: {data!r} (type: {type(data).__name__})",
        )

    def loads(self, data: bytes) -> Any:
        try:
            return json.loads(data)
        except (ValueError, TypeError) as e:
            raise SerializationError(
                message=f"Unable to deserialize as JSON: {data!r}", errors=(e,)
            )

    def dumps(self, data: Any) -> bytes:
        try:
            return json.dumps(
                data, default=self.default, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8", "surrogatepass")
        # This should be captured by the .default()
        # call but just in case we also wrap these.
        except (ValueError, UnicodeError, TypeError) as e:  # pragma: nocover
            raise SerializationError(
                message=f"Unable to serialize to JSON: {data!r} (type: {type(data).__name__})",
                errors=(e,),
            )


DEFAULT_SERIALIZERS = {
    JsonSerializer.mimetype: JsonSerializer(),
    TextSerializer.mimetype: TextSerializer(),
}


class Deserializer:
    def __init__(
        self,
        serializers: Optional[Mapping[str, Serializer]] = None,
        default_mimetype: str = "application/json",
    ):
        if serializers is None:
            serializers = DEFAULT_SERIALIZERS
        try:
            self.default = serializers[default_mimetype]
        except KeyError:
            raise ValueError(
                f"Must configure a serializer for the default mimetype {default_mimetype!r}"
            ) from None
        self.serializers = dict(serializers)

    def dumps(self, data: Any, mimetype: Optional[str] = None) -> bytes:
        return self._serializer_for_mimetype(mimetype).dumps(data)

    def loads(self, data: bytes, mimetype: Optional[str] = None) -> Any:
        return self._serializer_for_mimetype(mimetype).loads(data)

    def _serializer_for_mimetype(self, mimetype: Optional[str]) -> Serializer:
        # split out charset
        if mimetype is None:
            serializer = self.default
        else:
            mimetype, _, _ = mimetype.partition(";")
            try:
                serializer = self.serializers[mimetype]
            except KeyError:
                # Try for '<mimetype-supertype>/*' types after the specific type fails.
                try:
                    mimetype_supertype = mimetype.partition("/")[0]
                    serializer = self.serializers[f"{mimetype_supertype}/*"]
                except KeyError:
                    raise SerializationError(
                        f"Unknown mimetype, unable to deserialize: {mimetype}"
                    ) from None
        return serializer
