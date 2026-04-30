/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.example.springboot.qdrant;

import java.util.List;
import java.util.Map;

import io.qdrant.client.ValueFactory;
import io.qdrant.client.grpc.Collections;
import io.qdrant.client.grpc.Points;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ServiceStatus;
import org.apache.camel.component.qdrant.rag.RAGCreateCollection;
import org.apache.camel.component.qdrant.rag.RAGResultExtractor;
import org.apache.camel.support.DefaultExchange;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@CamelSpringBootTest
@SpringBootTest(classes = Application.class)
class MyCamelApplicationJUnit5Test {

    @Autowired
    private CamelContext camelContext;

    @Test
    void shouldLoadCamelContext() {
        assertEquals(ServiceStatus.Started, camelContext.getStatus());
        assertFalse(camelContext.getRoutes().isEmpty());
    }

    @Test
    void shouldLoadAllRoutes() {
        assertEquals(4, camelContext.getRoutes().size());
        assertNotNull(camelContext.getRoute("init-collection"));
        assertNotNull(camelContext.getRoute("index-documents"));
        assertNotNull(camelContext.getRoute("embed-and-store"));
        assertNotNull(camelContext.getRoute("rag-pipeline"));
    }

    @Test
    void shouldHaveQdrantAndOpenAIEndpoints() {
        assertFalse(camelContext.getEndpoints().stream()
                .filter(e -> e.getEndpointUri().startsWith("qdrant:")).toList().isEmpty());
        assertFalse(camelContext.getEndpoints().stream()
                .filter(e -> e.getEndpointUri().startsWith("openai:")).toList().isEmpty());
    }

    @Test
    void shouldCreateCollectionWithCorrectSize() throws Exception {
        RAGCreateCollection ragCreateCollection = new RAGCreateCollection();
        ragCreateCollection.setSize("768");
        ragCreateCollection.setDistance("Cosine");

        Exchange exchange = new DefaultExchange(camelContext);
        ragCreateCollection.process(exchange);

        Collections.VectorParams vectorParams = exchange.getIn().getBody(Collections.VectorParams.class);
        assertNotNull(vectorParams);
        assertEquals(768, vectorParams.getSize());
        assertEquals(Collections.Distance.Cosine, vectorParams.getDistance());
    }

    @Test
    void shouldExtractResultsFromScoredPoints() {
        Points.ScoredPoint point1 = Points.ScoredPoint.newBuilder()
                .setScore(0.95f)
                .putPayload("content", ValueFactory.value("Fly Me to the Moon"))
                .build();
        Points.ScoredPoint point2 = Points.ScoredPoint.newBuilder()
                .setScore(0.87f)
                .putPayload("content", ValueFactory.value("Moonlight Sonata"))
                .build();
        Points.ScoredPoint point3 = Points.ScoredPoint.newBuilder()
                .setScore(0.82f)
                .putPayload("content", ValueFactory.value("Dancing in the Moonlight"))
                .build();

        Exchange exchange = new DefaultExchange(camelContext);
        exchange.getIn().setBody(List.of(point1, point2, point3));

        RAGResultExtractor extractor = new RAGResultExtractor();
        extractor.setPayloadKey("content");
        List<Map<String, Object>> results = extractor.extract(exchange);

        assertEquals(3, results.size());
        assertEquals(1, results.get(0).get("rank"));
        assertEquals("Fly Me to the Moon", results.get(0).get("content"));
        assertEquals(0.95f, (float) results.get(0).get("score"), 0.01f);
        assertEquals(3, results.get(2).get("rank"));
        assertEquals("Dancing in the Moonlight", results.get(2).get("content"));
    }

}
