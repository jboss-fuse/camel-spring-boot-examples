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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.component.kafka.KafkaConstants;
import org.apache.camel.component.kafka.consumer.KafkaManualCommit;
import org.apache.camel.component.openai.OpenAIConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

/** Small contract mappings and demo checks; transport and orchestration stay in Camel routes. */
@Component
public class ClaimMessages {
    private static final Logger LOG = LoggerFactory.getLogger(ClaimMessages.class);
    private final ObjectMapper mapper = new ObjectMapper();
    private final String prompt;
    private final String instanceId;
    private final RecommendationOutput output;

    public ClaimMessages(@Value("${claims.ai.system-prompt-resource}") Resource prompt,
                         @Value("${claims.instance-id}") String instanceId,
                         RecommendationOutput output) throws Exception {
        String template = prompt.getContentAsString(StandardCharsets.UTF_8);
        if (!template.contains("{{decisionRules}}")) {
            throw new IllegalArgumentException("The system prompt must contain {{decisionRules}}");
        }
        this.prompt = template.replace("{{decisionRules}}", DecisionRules.prompt());
        this.instanceId = instanceId;
        this.output = output;
    }

    public void captureTransport(Exchange exchange) {
        exchange.setProperty("claimStarted", System.nanoTime());
        exchange.setProperty("claimCommit", exchange.getMessage().getHeader(KafkaConstants.MANUAL_COMMIT));
        exchange.setProperty("sourceTopic", exchange.getMessage().getHeader(KafkaConstants.TOPIC));
        exchange.setProperty("sourcePartition", exchange.getMessage().getHeader(KafkaConstants.PARTITION));
        exchange.setProperty("sourceOffset", exchange.getMessage().getHeader(KafkaConstants.OFFSET));
    }

    public void prepare(Exchange exchange) {
        ClaimEvent event = exchange.getMessage().getBody(ClaimEvent.class);
        if (event == null || !Identifiers.valid(event.eventId()) || !Identifiers.valid(event.claimId())
                || !Identifiers.valid(event.correlationId())) {
            throw new ClaimException("INVALID_EVENT");
        }
        exchange.setProperty("claimEvent", event);
    }

    public void finalPrompt(Exchange exchange) throws Exception {
        Map<?, ?> claim = exchange.getProperty("verifiedClaim", Map.class);
        Map<?, ?> coverage = exchange.getMessage().getBody(Map.class);
        if (!Boolean.TRUE.equals(claim.get("found"))) {
            coverage = Map.of("found", false);
        }
        exchange.setProperty("claimEvidence", Map.copyOf(claim));
        exchange.setProperty("coverageEvidence", Map.copyOf(coverage));
        // Preserve the evidence while the model response replaces the message.
        exchange.getMessage().removeHeaders("*");
        exchange.getMessage().setHeader(OpenAIConstants.SYSTEM_MESSAGE, prompt);
        exchange.getMessage().setBody(mapper.writeValueAsString(Map.of(
                "claimId", exchange.getProperty("claimEvent", ClaimEvent.class).claimId(),
                "claim", claim, "coverage", coverage)));
    }

    public void readRecommendation(Exchange exchange) {
        Recommendation result = output.read(exchange);
        ClaimEvent event = exchange.getProperty("claimEvent", ClaimEvent.class);
        if (!event.claimId().equals(result.claimId())) {
            throw new ClaimException("INVALID_AI_RESPONSE", "CLAIM_ID_MISMATCH");
        }
        exchange.setProperty("recommendation", result);
        exchange.setProperty("decisionModel", exchange.getMessage().getHeader(OpenAIConstants.RESPONSE_MODEL));
        exchange.getMessage().setHeader("claimId", event.claimId());
    }

    public void rememberClaim(Exchange exchange) {
        Map<?, ?> claim = exchange.getMessage().getBody(Map.class);
        exchange.setProperty("verifiedClaim", claim);
        exchange.getMessage().setHeader("memberId", claim.get("memberId"));
    }

    public void validateDecision(Exchange exchange) {
        Map<?, ?> claim = exchange.getProperty("verifiedClaim", Map.class);
        Map<?, ?> coverage = exchange.getMessage().getBody(Map.class);
        if (!Boolean.TRUE.equals(claim.get("found"))) {
            coverage = Map.of("found", false);
        }
        if (!claim.equals(exchange.getProperty("claimEvidence"))
                || !coverage.equals(exchange.getProperty("coverageEvidence"))) {
            throw new ClaimException("STALE_EVIDENCE");
        }
        Recommendation result = exchange.getProperty("recommendation", Recommendation.class);
        Recommendation expected = DecisionRules.evaluate(
                exchange.getProperty("claimEvent", ClaimEvent.class).claimId(), claim, coverage);
        if (!expected.equals(result)) {
            throw new ClaimException("INVALID_AI_RESPONSE", "RECOMMENDATION_FACTS_MISMATCH");
        }
        Map<String, Object> output = envelope(exchange);
        output.put("outcome", expected.outcome());
        output.put("reasonCodes", expected.reasonCodes());
        output.put("policyVersion", expected.policyVersion());
        output.put("evidenceSource", "JDBC");
        output.put("model", exchange.getProperty("decisionModel"));
        output.put("responseNormalized", Boolean.TRUE.equals(exchange.getProperty("claimResponseNormalized")));
        exchange.getMessage().setBody(output);
        LOG.info("claim_validated instance={} event={} outcome={} durationMs={}", instanceId,
                output.get("eventId"), expected.outcome(), elapsed(exchange));
    }

    public void published(Exchange exchange) {
        ClaimEvent event = exchange.getProperty("claimEvent", ClaimEvent.class);
        LOG.info("claim_published instance={} event={} durationMs={}", instanceId,
                event == null ? null : event.eventId(), elapsed(exchange));
    }

    public void lookupResult(Exchange exchange) {
        List<?> rows = exchange.getMessage().getBody(List.class);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("found", rows != null && !rows.isEmpty());
        if (rows != null && !rows.isEmpty()) {
            Map<?, ?> row = (Map<?, ?>) rows.get(0);
            row.forEach((key, value) -> result.put(key.toString(), value));
        }
        exchange.getMessage().setBody(result);
    }

    public void startTool(Exchange exchange) {
        exchange.setProperty("toolStarted", System.nanoTime());
    }

    public void finishTool(Exchange exchange) {
        long nanos = System.nanoTime() - exchange.getProperty("toolStarted", Long.class);
        LOG.info("tool_completed instance={} tool={} durationMicros={}", instanceId,
                exchange.getFromRouteId(), nanos / 1000);
    }

    public void failure(Exchange exchange) {
        Throwable cause = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Throwable.class);
        String stage = exchange.getProperty("claimStage", String.class);
        String code = "INPUT".equals(stage) ? "INVALID_EVENT"
                : "VERIFY".equals(stage) ? "DATA_LOOKUP_FAILED"
                : "PUBLISH".equals(stage) ? "RESULT_PUBLICATION_FAILED" : "AI_REQUEST_FAILED";
        String detail = null;
        for (Throwable current = cause; current != null; current = current.getCause()) {
            if (current instanceof ClaimException rejected) {
                code = rejected.code();
                detail = rejected.detail();
                break;
            }
        }
        Map<String, Object> output = envelope(exchange);
        output.put("errorCode", code);
        if (detail != null) {
            output.put("errorDetail", detail);
        }
        output.put("stage", stage);
        output.put("sourceTopic", exchange.getProperty("sourceTopic"));
        output.put("sourcePartition", exchange.getProperty("sourcePartition"));
        output.put("sourceOffset", exchange.getProperty("sourceOffset"));
        exchange.getMessage().setBody(output);
        LOG.warn("claim_failed instance={} event={} code={} detail={} durationMs={}", instanceId,
                output.get("eventId"), code, detail, elapsed(exchange));
    }

    private Map<String, Object> envelope(Exchange exchange) {
        Map<String, Object> output = new LinkedHashMap<>();
        ClaimEvent event = exchange.getProperty("claimEvent", ClaimEvent.class);
        output.put("eventId", event != null ? event.eventId() : null);
        output.put("claimId", event != null ? event.claimId() : null);
        output.put("correlationId", event != null ? event.correlationId() : null);
        output.put("instanceId", instanceId);
        output.put("processingMillis", elapsed(exchange));
        output.put("completedAt", Instant.now().toString());
        return output;
    }

    private long elapsed(Exchange exchange) {
        Long start = exchange.getProperty("claimStarted", Long.class);
        return start == null ? 0 : (System.nanoTime() - start) / 1_000_000;
    }

    public void commit(Exchange exchange) {
        KafkaManualCommit commit = exchange.getProperty("claimCommit", KafkaManualCommit.class);
        if (commit != null) {
            exchange.setProperty("claimStage", "COMMIT");
            try {
                commit.commit();
            } catch (Exception error) {
                throw new ClaimCommitException(error);
            }
            exchange.removeProperty("claimCommit");
        }
    }

    public void commitFailed(Exchange exchange) {
        LOG.warn("offset_commit_failed topic={} partition={} offset={}", exchange.getProperty("sourceTopic"),
                exchange.getProperty("sourcePartition"), exchange.getProperty("sourceOffset"));
    }

    public record Recommendation(String claimId, String outcome, List<String> reasonCodes, String policyVersion) {
    }
}
