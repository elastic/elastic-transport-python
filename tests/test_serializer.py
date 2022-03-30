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

import uuid
from datetime import date
from decimal import Decimal

import pytest

from elastic_transport import (
    JsonSerializer,
    NdjsonSerializer,
    SerializationError,
    SerializerCollection,
    TextSerializer,
)
from elastic_transport._serializer import DEFAULT_SERIALIZERS

serializers = SerializerCollection(DEFAULT_SERIALIZERS)


def test_date_serialization():
    assert b'{"d":"2010-10-01"}' == JsonSerializer().dumps({"d": date(2010, 10, 1)})


def test_decimal_serialization():
    assert b'{"d":3.8}' == JsonSerializer().dumps({"d": Decimal("3.8")})


def test_uuid_serialization():
    assert b'{"d":"00000000-0000-0000-0000-000000000003"}' == JsonSerializer().dumps(
        {"d": uuid.UUID("00000000-0000-0000-0000-000000000003")}
    )


def test_serializes_nan():
    assert b'{"d":NaN}' == JsonSerializer().dumps({"d": float("NaN")})


def test_raises_serialization_error_on_dump_error():
    with pytest.raises(SerializationError):
        JsonSerializer().dumps(object())
    with pytest.raises(SerializationError):
        TextSerializer().dumps({})


def test_raises_serialization_error_on_load_error():
    with pytest.raises(SerializationError):
        JsonSerializer().loads(object())
    with pytest.raises(SerializationError):
        JsonSerializer().loads(b"{{")


def test_unicode_is_handled():
    j = JsonSerializer()
    assert (
        j.dumps({"你好": "你好"})
        == b'{"\xe4\xbd\xa0\xe5\xa5\xbd":"\xe4\xbd\xa0\xe5\xa5\xbd"}'
    )
    assert j.loads(b'{"\xe4\xbd\xa0\xe5\xa5\xbd":"\xe4\xbd\xa0\xe5\xa5\xbd"}') == {
        "你好": "你好"
    }

    t = TextSerializer()
    assert t.dumps("你好") == b"\xe4\xbd\xa0\xe5\xa5\xbd"
    assert t.loads(b"\xe4\xbd\xa0\xe5\xa5\xbd") == "你好"


def test_unicode_surrogates_handled():
    j = JsonSerializer()
    assert (
        j.dumps({"key": "你好\uda6a"})
        == b'{"key":"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"}'
    )
    assert j.loads(b'{"key":"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"}') == {
        "key": "你好\uda6a"
    }

    t = TextSerializer()
    assert t.dumps("你好\uda6a") == b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"
    assert t.loads(b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa") == "你好\uda6a"


def test_deserializes_json_by_default():
    assert {"some": "data"} == serializers.loads(b'{"some":"data"}')


def test_deserializes_text_with_correct_ct():
    assert '{"some":"data"}' == serializers.loads(b'{"some":"data"}', "text/plain")
    assert '{"some":"data"}' == serializers.loads(
        b'{"some":"data"}', "text/plain; charset=whatever"
    )


def test_raises_serialization_error_on_unknown_mimetype():
    with pytest.raises(SerializationError) as e:
        serializers.loads(b"{}", "fake/type")
    assert (
        str(e.value)
        == "Unknown mimetype, not able to serialize or deserialize: fake/type"
    )


def test_raises_improperly_configured_when_default_mimetype_cannot_be_deserialized():
    with pytest.raises(ValueError) as e:
        SerializerCollection({})
    assert (
        str(e.value)
        == "Must configure a serializer for the default mimetype 'application/json'"
    )


def test_text_asterisk_works_for_all_text_types():
    assert serializers.loads(b"{}", "text/html") == "{}"
    assert serializers.dumps("{}", "text/html") == b"{}"


@pytest.mark.parametrize("should_strip", [False, b"\n", b"\r\n"])
def test_ndjson_loads(should_strip):
    serializer = NdjsonSerializer()
    data = (
        b'{"key":"value"}\n'
        b'{"number":0.1,"one":1}\n'
        b'{"list":[1,2,3]}\r\n'
        b'{"unicode":"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"}\r\n'
    )
    if should_strip:
        data = data.strip(should_strip)
    data = serializer.loads(data)

    assert data == [
        {"key": "value"},
        {"number": 0.1, "one": 1},
        {"list": [1, 2, 3]},
        {"unicode": "你好\uda6a"},
    ]


def test_ndjson_dumps():
    serializer = NdjsonSerializer()
    data = serializer.dumps(
        [
            {"key": "value"},
            {"number": 0.1, "one": 1},
            {"list": [1, 2, 3]},
            {"unicode": "你好\uda6a"},
            '{"key:"value"}',
            b'{"bytes":"too"}',
        ]
    )
    assert data == (
        b'{"key":"value"}\n'
        b'{"number":0.1,"one":1}\n'
        b'{"list":[1,2,3]}\n'
        b'{"unicode":"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"}\n'
        b'{"key:"value"}\n'
        b'{"bytes":"too"}\n'
    )
