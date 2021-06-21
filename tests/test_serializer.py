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
    Deserializer,
    JSONSerializer,
    SerializationError,
    TextSerializer,
)
from elastic_transport.serializer import DEFAULT_SERIALIZERS

deserializer = Deserializer(DEFAULT_SERIALIZERS)


def test_date_serialization():
    assert '{"d":"2010-10-01"}' == JSONSerializer().dumps({"d": date(2010, 10, 1)})


def test_decimal_serialization():
    assert '{"d":3.8}' == JSONSerializer().dumps({"d": Decimal("3.8")})


def test_uuid_serialization():
    assert '{"d":"00000000-0000-0000-0000-000000000003"}' == JSONSerializer().dumps(
        {"d": uuid.UUID("00000000-0000-0000-0000-000000000003")}
    )


def test_serializes_nan():
    assert '{"d":NaN}' == JSONSerializer().dumps({"d": float("NaN")})


def test_raises_serialization_error_on_dump_error():
    with pytest.raises(SerializationError):
        JSONSerializer().dumps(object())
    with pytest.raises(SerializationError):
        TextSerializer().dumps({})


def test_raises_serialization_error_on_load_error():
    with pytest.raises(SerializationError):
        JSONSerializer().loads(object())
    with pytest.raises(SerializationError):
        JSONSerializer().loads("")
    with pytest.raises(SerializationError):
        JSONSerializer().loads("{{")


@pytest.mark.parametrize("string", ["你好", b"\x00\x01"])
def test_strings_are_left_untouched(string):
    assert string == JSONSerializer().dumps(string)
    assert string == TextSerializer().dumps(string)


def test_deserializes_json_by_default():
    assert {"some": "data"} == deserializer.loads('{"some":"data"}')


def test_deserializes_text_with_correct_ct():
    assert '{"some":"data"}' == deserializer.loads('{"some":"data"}', "text/plain")
    assert '{"some":"data"}' == deserializer.loads(
        '{"some":"data"}', "text/plain; charset=whatever"
    )


def test_raises_serialization_error_on_unknown_mimetype():
    with pytest.raises(SerializationError) as e:
        deserializer.loads("{}", "text/html")
    assert str(e.value) == "Unknown mimetype, unable to deserialize: text/html"


def test_raises_improperly_configured_when_default_mimetype_cannot_be_deserialized():
    with pytest.raises(ValueError) as e:
        Deserializer({})
    assert str(e.value) == "Cannot find default serializer (application/json)"
