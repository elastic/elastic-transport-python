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

from __future__ import annotations

import contextlib
import os
import typing

try:
    from opentelemetry import trace

    _tracer: trace.Tracer | None = trace.get_tracer("elastic-transport")
except ModuleNotFoundError:
    _tracer = None


ENABLED_ENV_VAR = "OTEL_PYTHON_INSTRUMENTATION_ELASTICSEARCH_ENABLED"


class OpenTelemetry:
    def __init__(self, enabled: bool | None = None, tracer: trace.Tracer | None = None):
        if enabled is None:
            enabled = os.environ.get(ENABLED_ENV_VAR, "false") != "false"
        self.tracer = tracer or _tracer
        self.enabled = enabled and self.tracer is not None
        print(self.enabled)

    @contextlib.contextmanager
    def span(self, method: str) -> typing.Generator[None, None, None]:
        if not self.enabled or self.tracer is None:
            yield
            return

        span_name = method
        with self.tracer.start_as_current_span(span_name) as span:
            span.set_attribute("http.request.method", method)
            span.set_attribute("db.system", "elasticsearch")
            yield
