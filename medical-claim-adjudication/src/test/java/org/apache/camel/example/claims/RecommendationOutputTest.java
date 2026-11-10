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
package org.apache.camel.example.claims;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.apache.camel.Exchange;
import org.apache.camel.component.openai.OpenAIEndpoint;
import org.apache.camel.impl.DefaultCamelContext;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.*;

class RecommendationOutputTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String VALID = """
            {"claimId":"CLM-1001","outcome":"APPROVED","reasonCodes":["ACTIVE_COVERAGE","PROCEDURE_COVERED","WITHIN_LIMIT"],"policyVersion":"v1"}
            """;

    @Test
    void shouldSendStrictSchemaWithoutToolsAndNeverDowngradeOnProviderErrors() throws Exception {
        AtomicReference<JsonNode> received = new AtomicReference<>();
        AtomicReference<String> content = new AtomicReference<>(VALID);
        AtomicInteger status = new AtomicInteger(200);
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", request -> {
            try {
                requests.incrementAndGet();
                received.set(JSON.readTree(request.getRequestBody()));
                byte[] bytes = status.get() == 200 ? JSON.writeValueAsBytes(Map.of(
                        "id", "test", "object", "chat.completion", "created", 1, "model", "scripted",
                        "choices", List.of(Map.of("index", 0, "finish_reason", "stop", "message",
                                Map.of("role", "assistant", "content", content.get())))))
                        : "{\"error\":{\"message\":\"unsupported schema\",\"type\":\"invalid_request_error\"}}"
                                .getBytes(StandardCharsets.UTF_8);
                request.getResponseHeaders().set("Content-Type", "application/json");
                request.sendResponseHeaders(status.get(), bytes.length);
                request.getResponseBody().write(bytes);
            } finally {
                request.close();
            }
        });
        server.start();
        try (DefaultCamelContext context = new DefaultCamelContext()) {
            RecommendationOutput output = output("schema");
            OpenAIEndpoint endpoint = context.getEndpoint("openai:chat-completion?apiKey=test&model=scripted"
                    + "&baseUrl=http://127.0.0.1:" + server.getAddress().getPort() + "/v1"
                    + "&autoToolExecution=false&storeFullResponse=true&maxRetries=0&requestTimeout=2000&additionalBodyProperty.trace_id=test-trace",
                    OpenAIEndpoint.class);
            output.configure(endpoint);
            context.start();
            try (var producer = context.createProducerTemplate()) {
                Exchange response = producer.request(endpoint, exchange -> exchange.getMessage().setBody("Evaluate claim CLM-1001"));
                assertNull(response.getException());
                assertEquals("APPROVED", output.read(response).outcome());
                JsonNode format = received.get().path("response_format");
                assertEquals("json_schema", format.path("type").asText());
                assertEquals("test-trace", received.get().path("trace_id").asText());
                assertTrue(format.path("json_schema").path("strict").asBoolean());
                assertFalse(format.path("json_schema").path("schema").path("additionalProperties").asBoolean(true));
                assertEquals(4, format.path("json_schema").path("schema").path("required").size());
                assertTrue(received.get().path("tools").isMissingNode() || received.get().path("tools").isEmpty());

                content.set("```json\n" + VALID + "\n```");
                response = producer.request(endpoint, exchange -> exchange.getMessage().setBody("Evaluate claim CLM-1001"));
                Exchange fenced = response;
                assertEquals("INVALID_RESPONSE_JSON", assertThrows(ClaimException.class, () -> output.read(fenced)).detail());
                assertNull(response.getProperty("claimResponseNormalized"));

                for (int failure : List.of(400, 401, 429, 503)) {
                    status.set(failure);
                    int before = requests.get();
                    Exchange rejected = producer.request(endpoint, exchange -> exchange.getMessage().setBody("Evaluate claim CLM-1001"));
                    assertNotNull(rejected.getException());
                    assertEquals(before + 1, requests.get(), "No unconstrained retry after provider rejection");
                    assertTrue(received.get().path("response_format").path("json_schema").path("strict").asBoolean());
                }
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldRejectInvalidOutputPoliciesAndLimitsAtStartup() {
        assertThrows(IllegalArgumentException.class, () -> output("auto-fallback"));
        assertThrows(IllegalArgumentException.class, () -> new RecommendationOutput("schema", 0,
                new ClassPathResource("schemas/recommendation.json")));
    }

    private static RecommendationOutput output(String policy) throws Exception {
        return new RecommendationOutput(policy, 16384, new ClassPathResource("schemas/recommendation.json"));
    }
}
