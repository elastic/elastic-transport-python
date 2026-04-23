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

import pytest

import elastic_transport
from elastic_transport import client_utils

modules = pytest.mark.parametrize("module", [elastic_transport, client_utils])


@modules
def test__all__sorted(module):
    module_all = module.__all__.copy()
    # Optional dependencies are added at the end
    if "OrjsonSerializer" in module_all:
        module_all.remove("OrjsonSerializer")
    assert module_all == sorted(module_all)


@modules
def test__all__is_importable(module):
    assert {attr for attr in module.__all__ if hasattr(module, attr)} == set(
        module.__all__
    )


def test_module_rewritten():
    assert repr(elastic_transport.Transport) == "<class 'elastic_transport.Transport'>"
