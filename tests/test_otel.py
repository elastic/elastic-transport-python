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


from opentelemetry.sdk.trace import TracerProvider, export
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from elastic_transport._otel import OpenTelemetry


def test_span():
    tracer_provider = TracerProvider()
    memory_exporter = InMemorySpanExporter()
    span_processor = export.SimpleSpanProcessor(memory_exporter)
    tracer_provider.add_span_processor(span_processor)
    tracer = tracer_provider.get_tracer(__name__)

    otel = OpenTelemetry(enabled=True, tracer=tracer)
    with otel.span("GET"):
        pass

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].attributes == {
        "http.request.method": "GET",
        "db.system": "elasticsearch",
    }
