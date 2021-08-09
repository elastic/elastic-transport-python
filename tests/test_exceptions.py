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

from elastic_transport import TransportError


def test_exception_repr_and_str():
    e = TransportError({"errors": [{"status": 500}]}, status=500)
    assert repr(e) == "TransportError({'errors': [{'status': 500}]}, status=500)"
    assert str(e) == "[500] {'errors': [{'status': 500}]}"

    e = TransportError("error", errors=(ValueError("value error"),), status=500)
    assert repr(e) == "TransportError('error', status=500, errors={!r})".format(
        e.errors,
    )
    assert str(e) == "[500] error"

    e = TransportError("error", errors=(ValueError("value error"),))
    assert repr(e) == f"TransportError('error', errors={e.errors!r})"
    assert str(e) == "error"
