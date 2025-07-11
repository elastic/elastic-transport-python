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

from elastic_transport import JsonSerializer
from elastic_transport._otel import OpenTelemetrySpan


def setup_tracing():
    tracer_provider = TracerProvider()
    memory_exporter = InMemorySpanExporter()
    span_processor = export.SimpleSpanProcessor(memory_exporter)
    tracer_provider.add_span_processor(span_processor)
    tracer = tracer_provider.get_tracer(__name__)

    return tracer, memory_exporter


def test_no_span():
    # With telemetry disabled, those calls should not raise
    span = OpenTelemetrySpan(None)
    span.set_db_statement(JsonSerializer().dumps({"timeout": "1m"}))
    span.set_node_metadata(
        "localhost",
        9200,
        "http://localhost:9200/",
        "_ml/anomaly_detectors/my-job/_open",
    )
    span.set_elastic_cloud_metadata(
        {
            "X-Found-Handling-Cluster": "e9106fc68e3044f0b1475b04bf4ffd5f",
            "X-Found-Handling-Instance": "instance-0000000001",
        }
    )


def test_detailed_span():
    tracer, memory_exporter = setup_tracing()
    with tracer.start_as_current_span("ml.open_job") as otel_span:
        span = OpenTelemetrySpan(
            otel_span,
            endpoint_id="my-job/_open",
            body_strategy="omit",
        )

        span.set_db_statement(JsonSerializer().dumps({"timeout": "1m"}))
        span.set_node_metadata(
            "localhost",
            9200,
            "http://localhost:9200/",
            "_ml/anomaly_detectors/my-job/_open",
        )
        span.set_elastic_cloud_metadata(
            {
                "X-Found-Handling-Cluster": "e9106fc68e3044f0b1475b04bf4ffd5f",
                "X-Found-Handling-Instance": "instance-0000000001",
            }
        )

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "ml.open_job"
    assert spans[0].attributes == {
        "url.full": "http://localhost:9200/_ml/anomaly_detectors/my-job/_open",
        "server.address": "localhost",
        "server.port": 9200,
        "db.elasticsearch.cluster.name": "e9106fc68e3044f0b1475b04bf4ffd5f",
        "db.elasticsearch.node.name": "instance-0000000001",
    }


def test_db_statement():
    tracer, memory_exporter = setup_tracing()
    with tracer.start_as_current_span("search") as otel_span:
        span = OpenTelemetrySpan(otel_span, endpoint_id="search", body_strategy="raw")
        span.set_db_statement(JsonSerializer().dumps({"query": {"match_all": {}}}))

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "search"
    assert spans[0].attributes == {
        "db.statement": '{"query":{"match_all":{}}}',
    }
