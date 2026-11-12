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

import javax.sql.DataSource;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.kafka.KafkaConstants;
import org.apache.camel.component.kafka.consumer.KafkaManualCommit;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.test.spring.junit6.CamelSpringBootTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Exercises the real Camel OpenAI/AI Tool components; only model inference is scripted. */
@CamelSpringBootTest
@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "camel.main.run-controller=false",
        "management.server.port=0",
        "claims.kafka.input-endpoint=direct:incoming",
        "claims.reviews.input-endpoint=direct:reviewResults",
        "claims.human-decisions.input-endpoint=direct:humanCommands",
        "claims.human-decisions.commands-endpoint=mock:humanCommands",
        "claims.kafka.results-endpoint=mock:results",
        "claims.kafka.failures-endpoint=mock:failures",
        "claims.retry.delay-ms=1",
        "spring.datasource.url=jdbc:h2:mem:claim-test;DB_CLOSE_DELAY=-1",
        "spring.ai.mcp.server.streamable-http.mcp-endpoint=/claims-mcp",
        "claims.instance-id=test-instance"
})
class ClaimWorkflowTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicReference<String> MODE = new AtomicReference<>("normal");
    private static final AtomicInteger REQUESTS = new AtomicInteger();
    private static final AtomicReference<Runnable> FINAL_HOOK = new AtomicReference<>();
    private static final AtomicReference<Throwable> SERVER_FAILURE = new AtomicReference<>();
    private static HttpServer server;
    private static java.util.concurrent.ExecutorService serverThreads;

    @Autowired ProducerTemplate producer;
    @Autowired CamelContext context;
    @Autowired DataSource dataSource;
    @Autowired WebServerApplicationContext webContext;
    @LocalServerPort int httpPort;
    private MockEndpoint results;
    private MockEndpoint failures;
    private MockEndpoint humanCommands;

    @DynamicPropertySource
    static void modelEndpoint(DynamicPropertyRegistry properties) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverThreads = Executors.newFixedThreadPool(12);
        server.setExecutor(serverThreads);
        server.createContext("/v1/chat/completions", request -> {
            try {
                REQUESTS.incrementAndGet();
                JsonNode input = JSON.readTree(request.getRequestBody());
                if ("unavailable".equals(MODE.get())) {
                    byte[] body = "{\"error\":{\"message\":\"scripted outage\",\"type\":\"server_error\"}}"
                            .getBytes(StandardCharsets.UTF_8);
                    request.getResponseHeaders().set("Content-Type", "application/json");
                    request.sendResponseHeaders(503, body.length);
                    request.getResponseBody().write(body);
                } else {
                    byte[] body = JSON.writeValueAsBytes(response(input));
                    request.getResponseHeaders().set("Content-Type", "application/json");
                    request.sendResponseHeaders(200, body.length);
                    request.getResponseBody().write(body);
                }
            } catch (Throwable error) {
                SERVER_FAILURE.compareAndSet(null, error);
                request.sendResponseHeaders(500, -1);
            } finally {
                request.close();
            }
        });
        server.start();
        properties.add("camel.component.openai.base-url", () -> "http://127.0.0.1:" + server.getAddress().getPort() + "/v1");
        properties.add("camel.component.openai.model", () -> "scripted-model");
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop(0);
        if (serverThreads != null) serverThreads.shutdownNow();
    }

    @BeforeEach
    void reset() {
        new JdbcTemplate(dataSource).execute("DELETE FROM human_decisions");
        new JdbcTemplate(dataSource).execute("DELETE FROM manual_reviews");
        MODE.set("normal");
        REQUESTS.set(0);
        SERVER_FAILURE.set(null);
        FINAL_HOOK.set(null);
        results = context.getEndpoint("mock:results", MockEndpoint.class);
        failures = context.getEndpoint("mock:failures", MockEndpoint.class);
        results.reset();
        failures.reset();
        humanCommands = context.getEndpoint("mock:humanCommands", MockEndpoint.class);
        humanCommands.reset();
    }

    @Test
    void shouldUseJdbcEvidenceAndPublishApprovalBeforeCommit() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        results.expectedMessageCount(1);
        failures.expectedMessageCount(0);
        producer.sendBodyAndHeader("direct:incoming", event("CLM-1001", "approval"), KafkaConstants.MANUAL_COMMIT, commit);
        results.assertIsSatisfied();
        failures.assertIsSatisfied();
        JsonNode decision = body(results, 0);
        assertEquals("APPROVED", decision.path("outcome").asText());
        assertEquals("approval", decision.path("eventId").asText());
        assertEquals("test-instance", decision.path("instanceId").asText());
        assertEquals("CLM-1001", results.getExchanges().get(0).getMessage().getHeader(KafkaConstants.KEY));
        assertEquals(1, REQUESTS.get());
        assertEquals("JDBC", decision.path("evidenceSource").asText());
        assertFalse(decision.has("toolCalls"));
        verify(commit, times(1)).commit();
        assertNull(SERVER_FAILURE.get());
    }

    @Test
    void shouldReturnDenialsAndManualReview() throws Exception {
        results.expectedMessageCount(4);
        for (String id : List.of("CLM-1002", "CLM-1003", "CLM-1004", "CLM-9999")) {
            producer.sendBody("direct:incoming", event(id, id));
        }
        results.assertIsSatisfied();
        assertEquals("PROCEDURE_EXCLUDED", body(results, 0).path("reasonCodes").get(0).asText());
        assertEquals("LIMIT_EXCEEDED", body(results, 1).path("reasonCodes").get(0).asText());
        assertEquals("MANUAL_REVIEW", body(results, 2).path("outcome").asText());
        assertEquals("MISSING_COVERAGE", body(results, 2).path("reasonCodes").get(0).asText());
        assertEquals("MISSING_CLAIM", body(results, 3).path("reasonCodes").get(0).asText());
        assertTrue(failures.getExchanges().isEmpty());
        assertNull(SERVER_FAILURE.get());
    }

    @Test
    void shouldProcessTheUnchangedReadmeSamples() throws Exception {
        for (String sample : List.of("approved", "excluded", "over-limit", "missing-coverage", "human-approval", "invalid")) {
            producer.sendBody("direct:incoming", java.nio.file.Files.readString(java.nio.file.Path.of("samples", sample + ".json")));
        }
        assertEquals(5, results.getExchanges().size());
        assertEquals("APPROVED", body(results, 0).path("outcome").asText());
        assertEquals("PROCEDURE_EXCLUDED", body(results, 1).path("reasonCodes").get(0).asText());
        assertEquals("LIMIT_EXCEEDED", body(results, 2).path("reasonCodes").get(0).asText());
        assertEquals("MISSING_COVERAGE", body(results, 3).path("reasonCodes").get(0).asText());
        assertEquals("MISSING_COVERAGE", body(results, 4).path("reasonCodes").get(0).asText());
        assertEquals(1, failures.getExchanges().size());
        assertEquals("INVALID_EVENT", body(failures, 0).path("errorCode").asText());
        assertNull(SERVER_FAILURE.get());
    }

    @Test
    void shouldRejectMalformedEventsWithoutCallingModel() throws Exception {
        failures.expectedMessageCount(2);
        producer.sendBody("direct:incoming", "{bad-json");
        producer.sendBody("direct:incoming", "{\"eventId\":\"invalid\"}");
        failures.assertIsSatisfied();
        assertEquals(0, REQUESTS.get());
        assertEquals("INVALID_EVENT", body(failures, 0).path("errorCode").asText());
        assertEquals("INVALID_EVENT", body(failures, 1).path("errorCode").asText());
        assertTrue(results.getExchanges().isEmpty());
    }

    @Test
    void shouldRejectMalformedModelOutputAndUnsupportedApproval() throws Exception {
        failures.expectedMessageCount(2);
        MODE.set("invalid");
        producer.sendBody("direct:incoming", event("CLM-1001", "invalid-response"));
        MODE.set("approve-everything");
        producer.sendBody("direct:incoming", event("CLM-1004", "unsupported-approval"));
        failures.assertIsSatisfied();
        assertEquals("INVALID_AI_RESPONSE", body(failures, 0).path("errorCode").asText());
        assertEquals("INVALID_RESPONSE_JSON", body(failures, 0).path("errorDetail").asText());
        assertEquals("INVALID_AI_RESPONSE", body(failures, 1).path("errorCode").asText());
        assertEquals("RECOMMENDATION_FACTS_MISMATCH", body(failures, 1).path("errorDetail").asText());
        assertTrue(results.getExchanges().isEmpty());
    }

    @Test
    void shouldRejectUnexpectedFieldsWithoutExposingResponseContent() throws Exception {
        MODE.set("extra-field");
        producer.sendBody("direct:incoming", event("CLM-1001", "extra-fields"));
        assertEquals(1, failures.getExchanges().size());
        assertEquals("UNEXPECTED_RESPONSE_FIELDS", body(failures, 0).path("errorDetail").asText());
        assertFalse(body(failures, 0).toString().contains("unexpected"));
        assertTrue(results.getExchanges().isEmpty());
    }

    @Test
    void shouldUnwrapOnlyCompleteFencesAndStillValidateTheDecision() throws Exception {
        for (String mode : List.of("fenced", "fenced-unlabelled")) {
            MODE.set(mode);
            producer.sendBody("direct:incoming", event("CLM-1002", mode));
        }
        assertEquals(2, results.getExchanges().size());
        for (int i = 0; i < 2; i++) {
            assertEquals("DENIED", body(results, i).path("outcome").asText());
            assertTrue(body(results, i).path("responseNormalized").asBoolean());
        }
        assertTrue(failures.getExchanges().isEmpty());
        MODE.set("fenced-wrong");
        producer.sendBody("direct:incoming", event("CLM-1002", "fenced-wrong"));
        assertEquals("RECOMMENDATION_FACTS_MISMATCH", body(failures, 0).path("errorDetail").asText());
        assertEquals(2, results.getExchanges().size());
    }

    @Test
    void shouldRejectAmbiguousMalformedAndIncompleteFinalResponses() throws Exception {
        for (String mode : List.of("fenced-prose", "trailing", "duplicate", "missing-policy", "wrong-type",
                "oversized", "truncated", "refusal", "missing-finish", "unexpected-tool-call")) {
            MODE.set(mode);
            producer.sendBody("direct:incoming", event("CLM-1001", mode));
        }
        assertEquals(10, failures.getExchanges().size());
        assertTrue(results.getExchanges().isEmpty());
        assertEquals("INVALID_RECOMMENDATION_FIELDS", body(failures, 3).path("errorDetail").asText());
        assertEquals("INVALID_RECOMMENDATION_FIELDS", body(failures, 4).path("errorDetail").asText());
        assertEquals("RESPONSE_SIZE_LIMIT", body(failures, 5).path("errorDetail").asText());
        assertEquals("INCOMPLETE_AI_RESPONSE", body(failures, 6).path("errorDetail").asText());
        assertEquals("AI_REFUSAL", body(failures, 7).path("errorDetail").asText());
        assertEquals("INCOMPLETE_AI_RESPONSE", body(failures, 8).path("errorDetail").asText());
        assertEquals("UNEXPECTED_TOOL_CALL", body(failures, 9).path("errorDetail").asText());
        assertNull(SERVER_FAILURE.get());
    }

    @Test
    void shouldRequireManualReviewForDifferentCurrencies() throws Exception {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.update("UPDATE coverage SET currency = 'USD' WHERE member_id = 'MEM-501'");
        try {
            MODE.set("currency-mismatch");
            producer.sendBody("direct:incoming", event("CLM-1001", "currency-mismatch"));
            assertEquals("MANUAL_REVIEW", body(results, 0).path("outcome").asText());
            assertEquals("CURRENCY_MISMATCH", body(results, 0).path("reasonCodes").get(0).asText());
            assertEquals("DEMO-POLICY-v1", body(results, 0).path("policyVersion").asText());
            assertTrue(failures.getExchanges().isEmpty());
            MODE.set("normal"); // A schema-valid approval must still fail the independent currency check.
            producer.sendBody("direct:incoming", event("CLM-1001", "unsupported-currency-approval"));
            assertEquals("RECOMMENDATION_FACTS_MISMATCH", body(failures, 0).path("errorDetail").asText());
            assertEquals(1, results.getExchanges().size());
        } finally {
            jdbc.update("UPDATE coverage SET currency = 'EUR' WHERE member_id = 'MEM-501'");
        }
    }

    @Test
    void shouldRejectEvidenceThatChangesDuringTheFinalCall() throws Exception {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        FINAL_HOOK.set(() -> jdbc.update("UPDATE coverage SET policy_version = 'changed' WHERE member_id = 'MEM-501'"));
        try {
            producer.sendBody("direct:incoming", event("CLM-1001", "stale-evidence"));
            assertEquals("STALE_EVIDENCE", body(failures, 0).path("errorCode").asText());
            assertTrue(results.getExchanges().isEmpty());
            assertNull(SERVER_FAILURE.get());
        } finally {
            jdbc.update("UPDATE coverage SET policy_version = 'DEMO-POLICY-v1' WHERE member_id = 'MEM-501'");
        }
    }

    @Test
    void shouldBoundModelRetriesAndPreserveCorrelationOnFailure() throws Exception {
        MODE.set("unavailable");
        failures.expectedMessageCount(1);
        producer.sendBody("direct:incoming", event("CLM-1001", "outage"));
        failures.assertIsSatisfied();
        JsonNode failure = body(failures, 0);
        assertEquals("AI_REQUEST_FAILED", failure.path("errorCode").asText());
        assertEquals("outage", failure.path("eventId").asText());
        assertEquals("correlation-outage", failure.path("correlationId").asText());
        assertEquals(2, REQUESTS.get());
        assertFalse(failure.toString().contains("scripted outage"));
    }

    @Test
    void shouldKeepConcurrentConversationsAndRepliesIsolated() throws Exception {
        results.expectedMessageCount(12);
        var threads = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                int index = i;
                tasks.add(() -> {
                    producer.sendBody("direct:incoming", event("CLM-100" + (index % 4 + 1), "parallel-" + index));
                    return null;
                });
            }
            for (var completed : threads.invokeAll(tasks)) completed.get();
        } finally {
            threads.shutdownNow();
        }
        results.assertIsSatisfied();
        var ids = new java.util.HashSet<String>();
        for (Exchange received : results.getExchanges()) {
            JsonNode output = JSON.readTree(received.getMessage().getBody(String.class));
            String id = output.path("eventId").asText();
            assertTrue(ids.add(id));
            int index = Integer.parseInt(id.substring("parallel-".length()));
            assertEquals("CLM-100" + (index % 4 + 1), output.path("claimId").asText());
            assertEquals("correlation-" + id, output.path("correlationId").asText());
        }
        assertEquals(12, ids.size());
        assertEquals(12, REQUESTS.get());
        assertTrue(failures.getExchanges().isEmpty());
        assertNull(SERVER_FAILURE.get());
    }

    @Test
    void shouldUseJdbcParametersAndReturnAnInternalReply() {
        Map<?, ?> result = producer.requestBodyAndHeader("direct:lookupClaim", null, "claimId", "CLM-1001", Map.class);
        assertEquals("MEM-501", result.get("memberId"));
        assertThrows(Exception.class, () -> producer.requestBodyAndHeader("direct:lookupClaim", null,
                "claimId", "x' OR '1'='1", Map.class));
    }

    @Test
    void shouldPublishFailureBeforeCommittingIfResultPublicationFails() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        results.whenAnyExchangeReceived(exchange -> {
            verifyNoInteractions(commit);
            throw new IllegalStateException("scripted result publication failure");
        });
        failures.whenAnyExchangeReceived(exchange -> verifyNoInteractions(commit));
        try {
            failures.expectedMessageCount(1);
            producer.sendBodyAndHeader("direct:incoming", event("CLM-1001", "publication-failure"),
                    KafkaConstants.MANUAL_COMMIT, commit);
            failures.assertIsSatisfied();
            assertEquals("RESULT_PUBLICATION_FAILED", body(failures, 0).path("errorCode").asText());
            verify(commit, times(1)).commit();
        } finally {
            results.whenAnyExchangeReceived(exchange -> { });
            failures.whenAnyExchangeReceived(exchange -> { });
        }
    }

    @Test
    void shouldLeaveInputUncommittedWhenFailurePublicationFails() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        failures.whenAnyExchangeReceived(exchange -> {
            throw new IllegalStateException("scripted failure publication outage");
        });
        try {
            assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:incoming",
                    "{bad-json", KafkaConstants.MANUAL_COMMIT, commit));
            verifyNoInteractions(commit);
            assertTrue(results.getExchanges().isEmpty());
        } finally {
            failures.whenAnyExchangeReceived(exchange -> { });
        }
    }

    @Test
    void shouldExposeTheSameClaimToolsOverMcpOnUndertow() throws Exception {
        assertTrue(webContext.getWebServer().getClass().getName().contains("Undertow"));
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            var tools = client.listTools().tools();
            assertEquals(java.util.Set.of("get_claim_details", "get_member_coverage", "list_manual_reviews",
                            "submit_human_decision", "get_human_decision", "get_flow_metrics"),
                    tools.stream().map(McpSchema.Tool::name).collect(java.util.stream.Collectors.toSet()));
            var claimSchema = tools.stream().filter(tool -> tool.name().equals("get_claim_details"))
                    .findFirst().orElseThrow().inputSchema();
            assertTrue(((List<?>) claimSchema.get("required")).contains("claimId"));

            var claim = client.callTool(new McpSchema.CallToolRequest("get_claim_details",
                    Map.of("claimId", "CLM-1001")));
            assertFalse(Boolean.TRUE.equals(claim.isError()));
            JsonNode facts = JSON.readTree(((McpSchema.TextContent) claim.content().get(0)).text());
            assertEquals("MEM-501", facts.path("memberId").asText());

            var coverage = client.callTool(new McpSchema.CallToolRequest("get_member_coverage",
                    Map.of("memberId", facts.path("memberId").asText())));
            assertFalse(Boolean.TRUE.equals(coverage.isError()));
            JsonNode policy = JSON.readTree(((McpSchema.TextContent) coverage.content().get(0)).text());
            assertTrue(policy.path("active").asBoolean());
            assertEquals("DEMO-POLICY-v1", policy.path("policyVersion").asText());
        }
        assertEquals(0, REQUESTS.get(), "External fact lookups must not invoke the model");
        assertTrue(results.getExchanges().isEmpty());
        assertTrue(failures.getExchanges().isEmpty());
    }

    @Test
    void shouldReadRealRouteMetricsOverMcpWithoutAdditionalInferenceOrPublication() throws Exception {
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            var tool = client.listTools().tools().stream().filter(item -> item.name().equals("get_flow_metrics"))
                    .findFirst().orElseThrow();
            assertTrue(Boolean.TRUE.equals(tool.annotations().readOnlyHint()));
            JsonNode before = toolResult(client, "get_flow_metrics", Map.of("routeId", "claims-ingestion"));
            assertEquals("test-instance", before.path("instanceId").asText());
            assertEquals(1, before.path("routes").size());
            assertEquals(0, REQUESTS.get());
            assertTrue(results.getExchanges().isEmpty());
            assertTrue(failures.getExchanges().isEmpty());

            producer.sendBody("direct:incoming", event("CLM-1001", "metrics-approval"));
            int requests = REQUESTS.get();
            JsonNode after = toolResult(client, "get_flow_metrics", Map.of("routeId", "claims-ingestion"));
            JsonNode oldRoute = before.path("routes").get(0);
            JsonNode route = after.path("routes").get(0);
            assertEquals("claims-ingestion", route.path("routeId").asText());
            assertEquals(oldRoute.path("processed").asDouble() + 1, route.path("processed").asDouble());
            assertEquals(oldRoute.path("succeeded").asDouble() + 1, route.path("succeeded").asDouble());
            assertEquals(oldRoute.path("failed").asDouble(), route.path("failed").asDouble());
            assertEquals(0, route.path("inFlight").asDouble());
            assertEquals(oldRoute.path("timing").path("count").asLong() + 1,
                    route.path("timing").path("count").asLong());
            assertTrue(route.path("timing").path("meanMillis").asDouble() > 0);
            assertTrue(after.path("runtime").path("uptimeSeconds").asDouble() > 0);
            assertFalse(after.path("runtime").path("connectionPools").isEmpty());
            java.time.Instant.parse(after.path("snapshotAt").asText());
            java.time.Instant.parse(after.path("processStartedAt").asText());
            assertEquals(requests, REQUESTS.get(), "Metrics reads must not invoke inference");
            assertEquals(1, results.getExchanges().size(), "Metrics reads must not publish a result");
            assertTrue(failures.getExchanges().isEmpty());
        }
    }

    @Test
    void shouldListMetricsRoutesAndRejectUnknownMetricsFilters() throws Exception {
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            JsonNode snapshot = toolResult(client, "get_flow_metrics", Map.of());
            List<String> ids = new ArrayList<>();
            snapshot.path("routes").forEach(route -> ids.add(route.path("routeId").asText()));
            assertEquals(context.getRoutes().size() - 1, ids.size());
            assertEquals(ids.stream().sorted().toList(), ids);
            assertFalse(ids.contains(FlowMetrics.TOOL_ROUTE_ID), "Do not report the snapshot request as business work");
            assertTrue(ids.contains("claims-ingestion"));
            for (String id : List.of("not-a-route", " ", "claims-ingestion/*", FlowMetrics.TOOL_ROUTE_ID)) {
                var result = client.callTool(new McpSchema.CallToolRequest("get_flow_metrics", Map.of("routeId", id)));
                assertTrue(Boolean.TRUE.equals(result.isError()), id);
            }
        }
        assertEquals(0, REQUESTS.get());
        assertTrue(results.getExchanges().isEmpty());
        assertTrue(failures.getExchanges().isEmpty());
    }

    @Test
    void shouldReturnMissingRecordsAndRejectInvalidMcpArguments() throws Exception {
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            var missing = client.callTool(new McpSchema.CallToolRequest("get_claim_details",
                    Map.of("claimId", "CLM-9999")));
            assertFalse(Boolean.TRUE.equals(missing.isError()));
            assertFalse(JSON.readTree(((McpSchema.TextContent) missing.content().get(0)).text())
                    .path("found").asBoolean());

            var invalid = client.callTool(new McpSchema.CallToolRequest("get_claim_details",
                    Map.of("claimId", "x' OR '1'='1")));
            assertTrue(Boolean.TRUE.equals(invalid.isError()));
        }
        assertEquals(0, REQUESTS.get());
        assertTrue(results.getExchanges().isEmpty());
        assertTrue(failures.getExchanges().isEmpty());
    }

    @Test
    void shouldListManualReviewsOverMcpAfterAdjudication() throws Exception {
        producer.sendBody("direct:incoming", event("CLM-1004", "needs-review"));
        JsonNode decision = body(results, 0);
        assertEquals("MANUAL_REVIEW", decision.path("outcome").asText());
        int modelRequests = REQUESTS.get();
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        String published = results.getExchanges().get(0).getMessage().getBody(String.class);
        producer.sendBodyAndHeader("direct:reviewResults", published, KafkaConstants.MANUAL_COMMIT, commit);
        producer.sendBody("direct:reviewResults", published); // Kafka replay must not duplicate a review.
        verify(commit, times(1)).commit();

        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            JsonNode page = reviewList(client, Map.of());
            assertEquals(20, page.path("limit").asInt());
            assertEquals(0, page.path("offset").asInt());
            assertEquals(1, page.path("reviews").size());
            JsonNode review = page.path("reviews").get(0);
            assertEquals("needs-review", review.path("eventId").asText());
            assertEquals("CLM-1004", review.path("claimId").asText());
            assertEquals("correlation-needs-review", review.path("correlationId").asText());
            assertEquals("MISSING_COVERAGE", review.path("reasonCodes").get(0).asText());
            assertEquals(java.time.Instant.parse(decision.path("completedAt").asText()),
                    java.time.Instant.parse(review.path("completedAt").asText()));
        }
        assertEquals(modelRequests, REQUESTS.get(), "Listing reviews must not invoke inference");
        assertEquals(1, results.getExchanges().size(), "Listing reviews must not publish decisions");
        assertTrue(failures.getExchanges().isEmpty());
    }

    @Test
    void shouldListOnlyManualReviewsWithStableBoundedPages() throws Exception {
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            assertTrue(reviewList(client, Map.of()).path("reviews").isEmpty());
            for (String id : List.of("CLM-1001", "CLM-1002", "CLM-1004", "CLM-9999")) {
                producer.sendBody("direct:incoming", event(id, id));
            }
            for (Exchange result : results.getExchanges()) {
                producer.sendBody("direct:reviewResults", result.getMessage().getBody(String.class));
            }
            JsonNode page = reviewList(client, Map.of("limit", 1, "offset", 0));
            assertEquals(1, page.path("reviews").size());
            assertEquals("CLM-1004", page.path("reviews").get(0).path("claimId").asText());
            JsonNode next = reviewList(client, Map.of("limit", 1, "offset", 1));
            assertEquals("CLM-9999", next.path("reviews").get(0).path("claimId").asText());
            assertTrue(reviewList(client, Map.of("offset", 2)).path("reviews").isEmpty());
            for (Map<String, Object> args : List.<Map<String, Object>>of(
                    Map.of("limit", 0), Map.of("limit", 101), Map.of("offset", -1),
                    Map.of("limit", "1 OR 1=1"))) {
                assertTrue(Boolean.TRUE.equals(client.callTool(
                        new McpSchema.CallToolRequest("list_manual_reviews", args)).isError()));
            }
        }
    }

    @Test
    void shouldCommitIgnoredResultsAndLeaveFailedReviewWritesUncommitted() throws Exception {
        KafkaManualCommit ignored = mock(KafkaManualCommit.class);
        producer.sendBodyAndHeader("direct:reviewResults", "{\"outcome\":\"APPROVED\"}",
                KafkaConstants.MANUAL_COMMIT, ignored);
        verify(ignored, times(1)).commit();

        producer.sendBody("direct:incoming", event("CLM-1004", "storage-failure"));
        String published = results.getExchanges().get(0).getMessage().getBody(String.class);
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("ALTER TABLE manual_reviews RENAME TO unavailable_manual_reviews");
        try {
            assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:reviewResults", published,
                    KafkaConstants.MANUAL_COMMIT, commit));
            verifyNoInteractions(commit);
        } finally {
            jdbc.execute("ALTER TABLE unavailable_manual_reviews RENAME TO manual_reviews");
        }
        producer.sendBodyAndHeader("direct:reviewResults", published, KafkaConstants.MANUAL_COMMIT, commit);
        verify(commit, times(1)).commit();
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM manual_reviews", Integer.class));
    }

    @Test
    void shouldRecordAHumanConfirmedDecisionThroughMcpKafkaAndJdbc() throws Exception {
        openReview("human-review");
        int modelRequests = REQUESTS.get();
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            Map<String, Object> arguments = humanArguments("human-approval", "human-review", "APPROVED");
            JsonNode acknowledgment = toolResult(client, "submit_human_decision", arguments);
            assertEquals("SUBMITTED", acknowledgment.path("status").asText());
            assertEquals(1, humanCommands.getExchanges().size());
            assertEquals("human-review", humanCommands.getExchanges().get(0).getMessage().getHeader(KafkaConstants.KEY));
            assertFalse(toolResult(client, "get_human_decision", Map.of("decisionId", "human-approval"))
                    .path("found").asBoolean(), "Kafka acknowledgment is not a recorded decision");
            results.whenAnyExchangeReceived(exchange -> {
                verifyNoInteractions(commit);
                assertEquals("PENDING", new JdbcTemplate(dataSource).queryForObject(
                        "SELECT status FROM human_decisions WHERE decision_id = 'human-approval'", String.class));
            });
            String command = humanCommands.getExchanges().get(0).getMessage().getBody(String.class);
            try {
                producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit);
            } finally {
                results.whenAnyExchangeReceived(exchange -> { });
            }
            verify(commit, times(1)).commit();
            JsonNode result = body(results, 1);
            assertEquals("HUMAN_DECISION", result.path("eventType").asText());
            assertEquals("HUMAN", result.path("decisionSource").asText());
            assertEquals("human-approval", result.path("eventId").asText());
            assertEquals("human-review", result.path("reviewEventId").asText());
            assertEquals("CLM-1004", result.path("claimId").asText());
            assertEquals("correlation-human-review", result.path("correlationId").asText());
            assertEquals("APPROVED", result.path("outcome").asText());
            assertEquals("HUMAN_APPROVED", result.path("reasonCodes").get(0).asText());
            assertEquals("demo-reviewer", result.path("reviewerId").asText());
            assertEquals(arguments.get("reason"), result.path("reason").asText());
            assertTrue(reviewList(client, Map.of()).path("reviews").isEmpty());
            JsonNode status = toolResult(client, "get_human_decision", Map.of("decisionId", "human-approval"));
            assertEquals("PUBLISHED", status.path("status").asText());
            assertFalse(status.path("publishedAt").isNull());
            assertEquals("PUBLISHED", toolResult(client, "submit_human_decision", arguments).path("status").asText());
            assertEquals(1, humanCommands.getExchanges().size(), "An identical retry must not enqueue another command");
            producer.sendBody("direct:humanCommands", command);
            assertEquals(2, results.getExchanges().size(), "Kafka replay must not publish another final decision");
        }
        assertEquals(modelRequests, REQUESTS.get(), "Human decisions must not invoke the AI model");
        assertTrue(failures.getExchanges().isEmpty());
    }

    @Test
    void shouldRejectUnconfirmedAndInvalidHumanToolCallsWithoutSideEffects() throws Exception {
        openReview("confirmation-review");
        int modelRequests = REQUESTS.get();
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            for (String badField : List.of("confirmed", "outcome", "reason", "reviewerId", "decisionId", "reviewEventId")) {
                Map<String, Object> args = new LinkedHashMap<>(humanArguments("invalid-human", "confirmation-review", "APPROVED"));
                args.put(badField, "confirmed".equals(badField) ? false : " ");
                assertTrue(Boolean.TRUE.equals(client.callTool(
                        new McpSchema.CallToolRequest("submit_human_decision", args)).isError()), badField);
            }
            Map<String, Object> missing = new LinkedHashMap<>(humanArguments("missing-confirmation", "confirmation-review", "DENIED"));
            missing.remove("confirmed");
            assertTrue(Boolean.TRUE.equals(client.callTool(new McpSchema.CallToolRequest("submit_human_decision", missing)).isError()));
            assertTrue(Boolean.TRUE.equals(client.callTool(new McpSchema.CallToolRequest("submit_human_decision",
                    humanArguments("unknown-review", "not-a-review", "DENIED"))).isError()));
        }
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT COUNT(*) FROM human_decisions", Integer.class));
        assertTrue(humanCommands.getExchanges().isEmpty());
        assertEquals(modelRequests, REQUESTS.get());
    }

    @Test
    void shouldAuditAndRejectMissingReviewsConflictingIdsAndSecondDecisions() throws Exception {
        HumanDecision missing = humanCommand("missing-review-decision", "not-a-review", "DENIED");
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(missing));
        assertEquals("REVIEW_NOT_FOUND", body(failures, 0).path("errorDetail").asText());
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(missing));
        assertEquals(1, failures.getExchanges().size(), "A published rejection is idempotent");
        openReview("conflict-review");
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(humanCommand("first-decision", "conflict-review", "DENIED")));
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(humanCommand("second-decision", "conflict-review", "APPROVED")));
        assertEquals("REVIEW_ALREADY_CLAIMED", body(failures, 1).path("errorDetail").asText());
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(humanCommand("first-decision", "conflict-review", "APPROVED")));
        assertEquals("DECISION_ID_CONFLICT", body(failures, 2).path("errorDetail").asText());
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals("DENIED", jdbc.queryForObject("SELECT outcome FROM human_decisions WHERE decision_id = 'first-decision'", String.class));
        assertEquals("PUBLISHED", jdbc.queryForObject("SELECT status FROM human_decisions WHERE decision_id = 'first-decision'", String.class));
        assertEquals("REJECTED", jdbc.queryForObject("SELECT status FROM human_decisions WHERE decision_id = 'second-decision'", String.class));
        assertEquals(2, results.getExchanges().size(), "One automated review and one human final result");
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            assertTrue(Boolean.TRUE.equals(client.callTool(new McpSchema.CallToolRequest("submit_human_decision",
                    humanArguments("first-decision", "conflict-review", "APPROVED"))).isError()));
        }
    }

    @Test
    void shouldAllowOnlyOneOfTwoConcurrentHumanDecisionsToResolveAReview() throws Exception {
        openReview("contended-review");
        var threads = Executors.newFixedThreadPool(2);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (String outcome : List.of("APPROVED", "DENIED")) {
                tasks.add(() -> {
                    producer.sendBody("direct:humanCommands", JSON.writeValueAsString(
                            humanCommand("concurrent-" + outcome, "contended-review", outcome)));
                    return null;
                });
            }
            for (var done : threads.invokeAll(tasks)) done.get();
        } finally {
            threads.shutdownNow();
        }
        assertEquals(2, results.getExchanges().size());
        assertEquals(1, failures.getExchanges().size());
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM human_decisions WHERE status = 'PUBLISHED'", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM human_decisions WHERE status = 'REJECTED'", Integer.class));
    }

    @Test
    void shouldRetainPendingHumanDecisionAndOffsetWhenFinalPublicationFails() throws Exception {
        openReview("human-publication-review");
        String command = JSON.writeValueAsString(humanCommand("publication-decision", "human-publication-review", "APPROVED"));
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        results.whenAnyExchangeReceived(exchange -> { throw new IllegalStateException("scripted publication outage"); });
        try {
            assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit));
            verifyNoInteractions(commit);
        } finally {
            results.whenAnyExchangeReceived(exchange -> { });
        }
        assertEquals("PENDING", new JdbcTemplate(dataSource).queryForObject(
                "SELECT status FROM human_decisions WHERE decision_id = 'publication-decision'", String.class));
        Map<?, ?> pendingPage = producer.requestBody("direct:listManualReviews", null, Map.class);
        assertEquals(1, ((List<?>) pendingPage.get("reviews")).size());
        assertEquals("PENDING", ((Map<?, ?>) ((List<?>) pendingPage.get("reviews")).get(0)).get("reviewStatus"));
        try (McpSyncClient client = mcpClient()) {
            client.initialize();
            assertEquals("SUBMITTED", toolResult(client, "submit_human_decision",
                    humanArguments("publication-decision", "human-publication-review", "APPROVED")).path("status").asText());
            assertEquals(1, humanCommands.getExchanges().size(), "A pending decision can be retried with its original ID");
        }
        results.reset();
        producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit);
        verify(commit, times(1)).commit();
        assertEquals(1, results.getExchanges().size());
        assertEquals("PUBLISHED", new JdbcTemplate(dataSource).queryForObject(
                "SELECT status FROM human_decisions WHERE decision_id = 'publication-decision'", String.class));
    }

    @Test
    void shouldRetainHumanCommandOffsetWhenAuditStorageFails() throws Exception {
        openReview("human-storage-review");
        String command = JSON.writeValueAsString(humanCommand("storage-decision", "human-storage-review", "DENIED"));
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("ALTER TABLE human_decisions RENAME TO unavailable_human_decisions");
        try {
            assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit));
            verifyNoInteractions(commit);
        } finally {
            jdbc.execute("ALTER TABLE unavailable_human_decisions RENAME TO human_decisions");
        }
        producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit);
        verify(commit, times(1)).commit();
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM human_decisions", Integer.class));
    }

    @Test
    void shouldRetryUnpublishedHumanRejectionWithoutCommittingItsOffset() throws Exception {
        String command = JSON.writeValueAsString(humanCommand("rejection-outage", "unknown-review", "DENIED"));
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        failures.whenAnyExchangeReceived(exchange -> { throw new IllegalStateException("scripted failure-topic outage"); });
        try {
            assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit));
            verifyNoInteractions(commit);
        } finally {
            failures.whenAnyExchangeReceived(exchange -> { });
        }
        producer.sendBodyAndHeader("direct:humanCommands", command, KafkaConstants.MANUAL_COMMIT, commit);
        verify(commit, times(1)).commit();
        Map<?, ?> status = producer.requestBodyAndHeader("direct:getHumanDecision", null, "decisionId", "rejection-outage", Map.class);
        assertEquals("REJECTED", status.get("status"));
        assertNotNull(status.get("publishedAt"));
    }

    @Test
    void shouldRestoreHumanDecisionAuditAndClosureFromKafkaResults() throws Exception {
        openReview("replay-review");
        String original = results.getExchanges().get(0).getMessage().getBody(String.class);
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(humanCommand("replay-decision", "replay-review", "APPROVED")));
        String terminal = results.getExchanges().get(1).getMessage().getBody(String.class);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("DELETE FROM human_decisions");
        jdbc.execute("DELETE FROM manual_reviews");
        for (String event : List.of(terminal, original, terminal, original)) producer.sendBody("direct:reviewResults", event);
        Map<?, ?> page = producer.requestBody("direct:listManualReviews", null, Map.class);
        assertTrue(((List<?>) page.get("reviews")).isEmpty());
        Map<?, ?> status = producer.requestBodyAndHeader("direct:getHumanDecision", null, "decisionId", "replay-decision", Map.class);
        assertEquals("PUBLISHED", status.get("status"));
        assertEquals("demo-reviewer", status.get("reviewerId"));
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM human_decisions", Integer.class));
        assertEquals(2, results.getExchanges().size(), "Read-side replay must not publish decisions");
    }

    @Test
    void shouldRejectMalformedHumanKafkaCommandsWithoutCallingTheModel() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        Map<String, Object> stringConfirmation = new LinkedHashMap<>(humanArguments("string-confirmation", "unknown-review", "APPROVED"));
        stringConfirmation.put("confirmed", "true");
        Map<String, Object> absentConfirmation = new LinkedHashMap<>(humanArguments("absent-confirmation", "unknown-review", "APPROVED"));
        absentConfirmation.remove("confirmed");
        for (String invalid : List.of("{bad-json", JSON.writeValueAsString(stringConfirmation), JSON.writeValueAsString(absentConfirmation))) {
            producer.sendBodyAndHeader("direct:humanCommands", invalid, KafkaConstants.MANUAL_COMMIT, commit);
        }
        verify(commit, times(3)).commit();
        assertEquals(0, REQUESTS.get());
        assertEquals(3, failures.getExchanges().size());
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT COUNT(*) FROM human_decisions", Integer.class));
        assertTrue(results.getExchanges().isEmpty());
    }

    @Test
    void shouldPropagateCommitFailureWithoutPublishingClaimFailure() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        doThrow(new org.apache.kafka.clients.consumer.CommitFailedException()).when(commit).commit();
        assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:incoming",
                event("CLM-1001", "commit-failed"), KafkaConstants.MANUAL_COMMIT, commit));
        assertEquals(1, results.getExchanges().size());
        assertTrue(failures.getExchanges().isEmpty());
        assertEquals(1, REQUESTS.get());
        verify(commit, times(1)).commit();
    }

    @Test
    void shouldPropagateCommitFailureAfterPublishingInvalidClaimFailure() throws Exception {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        doThrow(new org.apache.kafka.clients.consumer.CommitFailedException()).when(commit).commit();
        assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:incoming", "{bad-json",
                KafkaConstants.MANUAL_COMMIT, commit));
        assertEquals(1, failures.getExchanges().size());
        assertEquals("INVALID_EVENT", body(failures, 0).path("errorCode").asText());
        assertTrue(results.getExchanges().isEmpty());
        verify(commit, times(1)).commit();
    }

    @Test
    void shouldPropagateCommitFailureWhenSkippingMalformedReview() {
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        doThrow(new org.apache.kafka.clients.consumer.CommitFailedException()).when(commit).commit();
        assertThrows(Exception.class, () -> producer.sendBodyAndHeader("direct:reviewResults", "[]",
                KafkaConstants.MANUAL_COMMIT, commit));
        verify(commit, times(1)).commit();
    }

    @Test
    void shouldOmitUnvalidatedIdentifiersFromFailuresAndKeys() throws Exception {
        String invalid = JSON.writeValueAsString(new ClaimEvent("forged\r\nlog", "X".repeat(500), "corr"));
        producer.sendBody("direct:incoming", invalid);
        JsonNode failure = body(failures, 0);
        assertTrue(failure.path("eventId").isNull());
        assertTrue(failure.path("claimId").isNull());
        assertNull(failures.getExchanges().get(0).getMessage().getHeader(KafkaConstants.KEY));
        assertEquals(0, REQUESTS.get());
    }

    @Test
    void shouldSkipPermanentProjectionErrorsAndContinueWithLaterReviews() throws Exception {
        openReview("valid-projection");
        String valid = results.getExchanges().get(0).getMessage().getBody(String.class);
        JsonNode event = JSON.readTree(valid);
        List<String> malformed = new ArrayList<>(List.of("[]", "null", "17", "{bad-json"));
        for (String field : List.of("completedAt", "reasonCodes", "eventId")) {
            var broken = (com.fasterxml.jackson.databind.node.ObjectNode) event.deepCopy();
            broken.remove(field);
            malformed.add(broken.toString());
        }
        var oversized = (com.fasterxml.jackson.databind.node.ObjectNode) event.deepCopy();
        oversized.putArray("reasonCodes").add("X".repeat(2001));
        malformed.add(oversized.toString());
        var badTime = (com.fasterxml.jackson.databind.node.ObjectNode) event.deepCopy();
        badTime.put("completedAt", 123);
        malformed.add(badTime.toString());
        for (String payload : malformed) {
            KafkaManualCommit commit = mock(KafkaManualCommit.class);
            producer.sendBodyAndHeader("direct:reviewResults", payload, KafkaConstants.MANUAL_COMMIT, commit);
            verify(commit).commit();
        }
        var later = (com.fasterxml.jackson.databind.node.ObjectNode) event.deepCopy();
        later.put("eventId", "later-projection");
        producer.sendBody("direct:reviewResults", later.toString());
        assertEquals(2, new JdbcTemplate(dataSource).queryForObject("SELECT COUNT(*) FROM manual_reviews", Integer.class));
    }

    @Test
    void shouldSortLegacyAndNewReviewTimestampsChronologically() throws Exception {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        for (String timestamp : List.of("2026-11-12T10:00:00.500Z", "2026-11-12T10:00:00Z",
                "2026-11-12T10:00:00.123456Z", "2026-11-12T10:00:00.123Z")) {
            jdbc.update("INSERT INTO manual_reviews(event_id, claim_id, correlation_id, reason_codes, completed_at) VALUES(?,?,?,?,?)",
                    "time-" + timestamp, "CLM-1004", "corr", "[\"MISSING_COVERAGE\"]", timestamp);
        }
        Map<?, ?> page = producer.requestBody("direct:listManualReviews", null, Map.class);
        List<?> reviews = (List<?>) page.get("reviews");
        List<String> ordered = reviews.stream().map(r -> ((Map<?, ?>) r).get("completedAt").toString()).toList();
        assertEquals(List.of("2026-11-12T10:00:00Z", "2026-11-12T10:00:00.123Z",
                "2026-11-12T10:00:00.123456Z", "2026-11-12T10:00:00.500Z"), ordered);
    }

    @Test
    void shouldSkipConflictingHumanProjectionWithoutMarkingAnotherDecisionPublished() throws Exception {
        openReview("projection-conflict");
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(
                humanCommand("winning-decision", "projection-conflict", "APPROVED")));
        var conflicting = (com.fasterxml.jackson.databind.node.ObjectNode) JSON.readTree(
                results.getExchanges().get(1).getMessage().getBody(String.class));
        conflicting.put("eventId", "conflicting-decision");
        conflicting.put("decisionId", "conflicting-decision");
        KafkaManualCommit commit = mock(KafkaManualCommit.class);
        producer.sendBodyAndHeader("direct:reviewResults", conflicting.toString(), KafkaConstants.MANUAL_COMMIT, commit);
        verify(commit).commit();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals("winning-decision", jdbc.queryForObject("SELECT resolution_decision_id FROM manual_reviews", String.class));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM human_decisions WHERE decision_id = 'conflicting-decision'", Integer.class));
    }

    @Test
    void shouldPreservePublishedStatusWhenRejectionMarkerRacesWithProjection() throws Exception {
        openReview("terminal-race");
        producer.sendBody("direct:humanCommands", JSON.writeValueAsString(humanCommand("terminal-decision", "terminal-race", "APPROVED")));
        producer.sendBodyAndHeaders("direct:markHumanDecisionPublished", null,
                Map.of("decisionId", "terminal-decision", "terminalStatus", "REJECTED", "publishedAt", "later"));
        assertEquals("PUBLISHED", new JdbcTemplate(dataSource).queryForObject(
                "SELECT status FROM human_decisions WHERE decision_id = 'terminal-decision'", String.class));
    }

    private void openReview(String eventId) throws Exception {
        producer.sendBody("direct:incoming", event("CLM-1004", eventId));
        producer.sendBody("direct:reviewResults", results.getExchanges().get(results.getExchanges().size() - 1)
                .getMessage().getBody(String.class));
    }

    private static HumanDecision humanCommand(String decisionId, String reviewId, String outcome) {
        return new HumanDecision(decisionId, reviewId, outcome, "demo-reviewer", "Verified member's enrollment externally.", true);
    }

    private static Map<String, Object> humanArguments(String decisionId, String reviewId, String outcome) {
        HumanDecision command = humanCommand(decisionId, reviewId, outcome);
        return Map.of("decisionId", command.decisionId(), "reviewEventId", command.reviewEventId(),
                "outcome", command.outcome(), "reviewerId", command.reviewerId(), "reason", command.reason(), "confirmed", true);
    }

    private JsonNode toolResult(McpSyncClient client, String name, Map<String, Object> args) throws Exception {
        var response = client.callTool(new McpSchema.CallToolRequest(name, args));
        assertFalse(Boolean.TRUE.equals(response.isError()));
        return JSON.readTree(((McpSchema.TextContent) response.content().get(0)).text());
    }

    private JsonNode reviewList(McpSyncClient client, Map<String, Object> arguments) throws Exception {
        var response = client.callTool(new McpSchema.CallToolRequest("list_manual_reviews", arguments));
        assertFalse(Boolean.TRUE.equals(response.isError()));
        return JSON.readTree(((McpSchema.TextContent) response.content().get(0)).text());
    }

    private McpSyncClient mcpClient() {
        var transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + httpPort)
                .endpoint("/claims-mcp").build();
        return McpClient.sync(transport).requestTimeout(Duration.ofSeconds(10)).build();
    }

    private static String event(String claimId, String eventId) throws Exception {
        return JSON.writeValueAsString(new ClaimEvent(eventId, claimId, "correlation-" + eventId));
    }

    private static JsonNode body(MockEndpoint endpoint, int index) throws Exception {
        return JSON.readTree(endpoint.getExchanges().get(index).getMessage().getBody(String.class));
    }

    private static Map<String, Object> response(JsonNode request) throws Exception {
        assertTrue(request.path("tools").isMissingNode() || request.path("tools").isEmpty());
        assertEquals(768, request.path("max_completion_tokens").asInt());
        assertFalse(request.has("response_format"));
        assertEquals(0.0, request.path("temperature").asDouble(-1));
        String user = "";
        for (JsonNode message : request.path("messages")) {
            if ("user".equals(message.path("role").asText())) user = message.path("content").asText();
        }
        JsonNode evidence = JSON.readTree(user);
        assertTrue(evidence.has("claim"));
        assertTrue(evidence.has("coverage"));
        Runnable hook = FINAL_HOOK.getAndSet(null);
        if (hook != null) hook.run();
        return finalResponse(evidence);
    }

    private static Map<String, Object> finalResponse(JsonNode evidence) throws Exception {
        String claimId = evidence.path("claimId").asText();
        // Script fixture outcomes, independent of the application's business validator.
        String outcome = "APPROVED";
        List<String> reasons = List.of("ACTIVE_COVERAGE", "PROCEDURE_COVERED", "WITHIN_LIMIT");
        String policy = "DEMO-POLICY-v1";
        switch (claimId) {
            case "CLM-1002" -> { outcome = "DENIED"; reasons = List.of("PROCEDURE_EXCLUDED"); }
            case "CLM-1003" -> { outcome = "DENIED"; reasons = List.of("LIMIT_EXCEEDED"); }
            case "CLM-1004" -> { outcome = "MANUAL_REVIEW"; reasons = List.of("MISSING_COVERAGE"); policy = null; }
            case "CLM-9999" -> { outcome = "MANUAL_REVIEW"; reasons = List.of("MISSING_CLAIM"); policy = null; }
            default -> { }
        }
        String mode = MODE.get();
        if ("currency-mismatch".equals(mode)) { outcome = "MANUAL_REVIEW"; reasons = List.of("CURRENCY_MISMATCH"); }
        if ("approve-everything".equals(mode) || "fenced-wrong".equals(mode)) outcome = "APPROVED";
        var decision = new ClaimMessages.Recommendation(evidence.path("claimId").asText(), outcome, reasons, policy);
        String content = JSON.writeValueAsString(decision);
        content = switch (mode) {
            case "invalid" -> "not JSON";
            case "extra-field" -> content.substring(0, content.length() - 1) + ",\"unexpected\":true}";
            case "fenced", "fenced-wrong" -> "```json\n" + content + "\n```";
            case "fenced-unlabelled" -> "```\n" + content + "\n```";
            case "fenced-prose" -> "Here is the result:\n```json\n" + content + "\n```";
            case "trailing" -> content + " {}";
            case "duplicate" -> content.replace("\"claimId\":", "\"claimId\":\"wrong\",\"claimId\":");
            case "missing-policy" -> content.replace(",\"policyVersion\":\"DEMO-POLICY-v1\"", "");
            case "wrong-type" -> content.replace("[\"ACTIVE_COVERAGE\",\"PROCEDURE_COVERED\",\"WITHIN_LIMIT\"]", "[1]");
            case "oversized" -> " ".repeat(17000) + content;
            default -> content;
        };
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", "assistant");
        message.put("content", content);
        if ("refusal".equals(mode)) message.put("refusal", "scripted refusal");
        if ("unexpected-tool-call".equals(mode)) {
            message.put("tool_calls", List.of(toolCall("unexpected", "get_claim_details", "claimId", "CLM-1001")));
        }
        Map<String, Object> choice = new LinkedHashMap<>();
        choice.put("index", 0);
        choice.put("message", message);
        if (!"missing-finish".equals(mode)) choice.put("finish_reason", "truncated".equals(mode) ? "length" : "stop");
        return Map.of("id", "chatcmpl-final", "object", "chat.completion", "created", 1, "model", "scripted-model",
                "choices", List.of(choice));
    }

    private static Map<String, Object> toolCall(String id, String name, String parameter, String value) throws Exception {
        return Map.of("id", id, "type", "function", "function",
                Map.of("name", name, "arguments", JSON.writeValueAsString(Map.of(parameter, value))));
    }
}
