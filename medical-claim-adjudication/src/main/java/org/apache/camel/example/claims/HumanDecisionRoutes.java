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

import java.time.DateTimeException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangePattern;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.builder.PredicateBuilder;
import org.apache.camel.component.jdbc.JdbcConstants;
import org.apache.camel.component.kafka.KafkaConstants;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** MCP submits commands; Kafka consumers own decision recording and publication. */
@Component
public class HumanDecisionRoutes extends RouteBuilder {
    private static final String INSERT_PENDING = """
            INSERT INTO human_decisions
                (decision_id, review_event_id, outcome, reviewer_id, reason, submitted_at, status)
            SELECT :?decisionId, :?reviewEventId, :?outcome, :?reviewerId, :?reason, :?submittedAt, 'PENDING'
            WHERE NOT EXISTS (SELECT 1 FROM human_decisions WHERE decision_id = :?decisionId)
            """;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ClaimMessages messages;
    private final int retries;
    private final long retryDelay;

    public HumanDecisionRoutes(ClaimMessages messages,
                               @Value("${claims.retry.maximum-redeliveries}") int retries,
                               @Value("${claims.retry.delay-ms}") long retryDelay) {
        this.messages = messages;
        this.retries = retries;
        this.retryDelay = retryDelay;
    }

    @Override
    public void configure() {
        errorHandler(defaultErrorHandler().maximumRedeliveries(retries).redeliveryDelay(retryDelay)
                .logExhausted(false).logStackTrace(false));

        from("ai-tool:submit_human_decision?tags={{claims.reviews.tool-tags}}"
                + "&description=Submit a human-confirmed APPROVED or DENIED decision for a manual-review event; call only after explicit human confirmation; returns submission status"
                + "&parameter.decisionId=string&parameter.decisionId.required=true"
                + "&parameter.decisionId.description=Unique stable ID; reuse exactly for retries"
                + "&parameter.reviewEventId=string&parameter.reviewEventId.required=true"
                + "&parameter.reviewEventId.description=eventId returned by list_manual_reviews"
                + "&parameter.outcome=string&parameter.outcome.required=true"
                + "&parameter.outcome.description=APPROVED or DENIED as explicitly selected by the reviewer"
                + "&parameter.reviewerId=string&parameter.reviewerId.required=true"
                + "&parameter.reason=string&parameter.reason.required=true"
                + "&parameter.reason.description=Human-supplied rationale from 1 to 1000 characters"
                + "&parameter.confirmed=boolean&parameter.confirmed.required=true"
                + "&parameter.confirmed.description=true only after the human explicitly confirms this decision"
                + "&readOnlyHint=false&destructiveHint=true&idempotentHint=true")
            .routeId("submit-human-decision-tool").startupOrder(23)
            .errorHandler(noErrorHandler())
            .process(messages::startTool)
            .process(this::prepareSubmission)
            .to(ExchangePattern.InOut, "direct:getHumanDecision")
            .process(this::submissionStatus)
            .choice()
                .when(exchangeProperty("humanSubmit").isEqualTo(true))
                    .to(ExchangePattern.InOut, "direct:getReviewForDecision")
                    .process(this::checkOpenReview)
                    .marshal().json(JsonLibrary.Jackson).convertBodyTo(String.class)
                    .removeHeaders("*")
                    .setHeader(KafkaConstants.KEY, simple("${exchangeProperty.humanCommand.reviewEventId}"))
                    .to("{{claims.human-decisions.commands-endpoint}}")
                    .process(this::submissionAcknowledgment)
            .end()
            .marshal().json(JsonLibrary.Jackson).convertBodyTo(String.class)
            .process(messages::finishTool);

        from("ai-tool:get_human_decision?tags={{claims.reviews.tool-tags}}"
                + "&description=Get a submitted human decision and its PENDING, PUBLISHED or REJECTED status by decision ID"
                + "&parameter.decisionId=string&parameter.decisionId.required=true&readOnlyHint=true")
            .routeId("get-human-decision-tool").startupOrder(24)
            .errorHandler(noErrorHandler())
            .process(messages::startTool)
            .to(ExchangePattern.InOut, "direct:getHumanDecision")
            .marshal().json(JsonLibrary.Jackson).convertBodyTo(String.class)
            .process(messages::finishTool);

        from("direct:getHumanDecision").routeId("human-decision-lookup").startupOrder(13)
            .errorHandler(noErrorHandler())
            .validate(exchange -> Identifiers.valid(exchange.getMessage().getHeader("decisionId")))
            .setBody(constant("""
                    SELECT decision_id AS "decisionId", review_event_id AS "reviewEventId", outcome AS "outcome",
                           reviewer_id AS "reviewerId", reason AS "reason", submitted_at AS "submittedAt",
                           status AS "status", rejection_code AS "errorCode", published_at AS "publishedAt"
                    FROM human_decisions WHERE decision_id = :?decisionId
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(messages::lookupResult);

        from("direct:getReviewForDecision").routeId("human-decision-review-lookup").startupOrder(14)
            .errorHandler(noErrorHandler())
            .setBody(constant("""
                    SELECT event_id AS "reviewEventId", claim_id AS "claimId", correlation_id AS "correlationId",
                           resolution_decision_id AS "resolutionDecisionId"
                    FROM manual_reviews WHERE event_id = :?reviewEventId
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(messages::lookupResult);

        from("{{claims.human-decisions.input-endpoint}}").routeId("human-decision-consumer").startupOrder(95)
            .process(messages::captureTransport)
            .removeHeaders("*")
            .process(this::prepareIncoming)
            .choice()
                .when(exchangeProperty("humanRejectCode").isNull())
                    .setBody(constant(INSERT_PENDING)).to("{{claims.jdbc.endpoint}}")
                    .to(ExchangePattern.InOut, "direct:getHumanDecision")
                    .process(this::storedDecision)
                    .choice()
                        .when(PredicateBuilder.and(exchangeProperty("humanSkip").isNotEqualTo(true),
                                exchangeProperty("humanRejectCode").isNull()))
                            .to(ExchangePattern.InOut, "direct:getReviewForDecision")
                            .process(this::decisionReview)
                            .choice()
                                .when(exchangeProperty("humanRejectCode").isNull())
                                    .setBody(constant("""
                                            UPDATE manual_reviews SET resolution_decision_id = :?decisionId
                                            WHERE event_id = :?reviewEventId
                                              AND (resolution_decision_id IS NULL OR resolution_decision_id = :?decisionId)
                                            """))
                                    .to("{{claims.jdbc.endpoint}}")
                                    .process(this::reviewClaimed)
                            .end()
                    .end()
            .end()
            .choice()
                .when(exchangeProperty("humanSkip").isNotEqualTo(true))
                    .choice()
                        .when(exchangeProperty("humanRejectCode").isNotNull())
                            .to("direct:publishHumanRejection")
                        .otherwise()
                            .to("direct:publishHumanDecision")
                    .end()
            .end()
            .process(messages::commit);

        from("direct:publishHumanDecision").routeId("human-decision-publication").startupOrder(32)
            .errorHandler(noErrorHandler())
            .process(this::finalDecision)
            .marshal().json(JsonLibrary.Jackson).convertBodyTo(String.class)
            .removeHeaders("*")
            .setHeader(KafkaConstants.KEY, simple("${exchangeProperty.humanReview[claimId]}"))
            .to("{{claims.kafka.results-endpoint}}")
            .process(exchange -> terminalParameters(exchange, "PUBLISHED"))
            .to("direct:markHumanDecisionPublished");

        from("direct:publishHumanRejection").routeId("human-decision-rejection").startupOrder(33)
            .errorHandler(noErrorHandler())
            .choice()
                .when(exchangeProperty("humanCanRecord").isEqualTo(true))
                    .process(this::parameters)
                    .setHeader("rejectionCode", exchangeProperty("humanRejectCode"))
                    .setBody(constant("""
                            UPDATE human_decisions SET status = 'REJECTED', rejection_code = :?rejectionCode
                            WHERE decision_id = :?decisionId AND status <> 'PUBLISHED'
                            """))
                    .to("{{claims.jdbc.endpoint}}")
            .end()
            .process(this::rejection)
            .marshal().json(JsonLibrary.Jackson).convertBodyTo(String.class)
            .removeHeaders("*")
            .setHeader(KafkaConstants.KEY, simple("${exchangeProperty.humanKey}"))
            .to("{{claims.kafka.failures-endpoint}}")
            .choice()
                .when(exchangeProperty("humanCanRecord").isEqualTo(true))
                    .process(exchange -> terminalParameters(exchange, "REJECTED"))
                    .to("direct:markHumanDecisionPublished")
            .end();

        from("direct:markHumanDecisionPublished").routeId("human-decision-publication-marker").startupOrder(15)
            .errorHandler(noErrorHandler())
            .setBody(constant("""
                    UPDATE human_decisions SET status = :?terminalStatus, published_at = :?publishedAt
                    WHERE decision_id = :?decisionId
                      AND (:?terminalStatus = 'PUBLISHED' OR status <> 'PUBLISHED')
                    """))
            .to("{{claims.jdbc.endpoint}}");

        from("direct:projectHumanDecision").routeId("human-decision-projection").startupOrder(16)
            .errorHandler(noErrorHandler())
            .process(this::projectionParameters)
            .to("direct:getHumanDecision")
            .process(exchange -> {
                Map<?, ?> stored = exchange.getMessage().getBody(Map.class);
                if (Boolean.TRUE.equals(stored.get("found"))
                        && !sameCommand(exchange.getProperty("humanCommand", HumanDecision.class), stored)) {
                    throw new InvalidReviewEventException();
                }
            })
            .to("direct:getReviewForDecision")
            .process(this::checkProjectionReview)
            .setBody(constant("""
                    UPDATE manual_reviews SET resolution_decision_id = :?decisionId
                    WHERE event_id = :?reviewEventId AND claim_id = :?claimId AND correlation_id = :?correlationId
                      AND (resolution_decision_id IS NULL OR resolution_decision_id = :?decisionId)
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(exchange -> {
                if (Boolean.TRUE.equals(exchange.getProperty("projectionReviewExists"))
                        && !Integer.valueOf(1).equals(exchange.getMessage().getHeader(JdbcConstants.JDBC_UPDATE_COUNT, Integer.class))) {
                    throw new InvalidReviewEventException();
                }
            })
            .setBody(constant(INSERT_PENDING)).to("{{claims.jdbc.endpoint}}")
            .setBody(constant("""
                    UPDATE human_decisions SET status = 'PUBLISHED', published_at = :?publishedAt
                    WHERE decision_id = :?decisionId AND review_event_id = :?reviewEventId
                      AND outcome = :?outcome AND reviewer_id = :?reviewerId AND reason = :?reason
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(exchange -> {
                if (!Integer.valueOf(1).equals(exchange.getMessage().getHeader(JdbcConstants.JDBC_UPDATE_COUNT, Integer.class))) {
                    throw new InvalidReviewEventException();
                }
            });
    }

    private void checkProjectionReview(Exchange exchange) {
        Map<?, ?> review = exchange.getMessage().getBody(Map.class);
        boolean exists = Boolean.TRUE.equals(review.get("found"));
        exchange.setProperty("projectionReviewExists", exists);
        if (exists && (!Objects.equals(review.get("claimId"), exchange.getMessage().getHeader("claimId"))
                || !Objects.equals(review.get("correlationId"), exchange.getMessage().getHeader("correlationId"))
                || (review.get("resolutionDecisionId") != null
                    && !Objects.equals(review.get("resolutionDecisionId"), exchange.getMessage().getHeader("decisionId"))))) {
            throw new InvalidReviewEventException();
        }
    }

    private HumanDecision validate(HumanDecision command) {
        if (command == null || !Identifiers.valid(command.decisionId()) || !Identifiers.valid(command.reviewEventId())
                || !Identifiers.valid(command.reviewerId()) || !command.confirmed()
                || !Set.of("APPROVED", "DENIED").contains(Objects.toString(command.outcome(), ""))
                || command.reason() == null || command.reason().isBlank() || command.reason().length() > 1000) {
            throw new IllegalArgumentException("A confirmed APPROVED or DENIED decision, valid IDs, reviewer and reason are required");
        }
        return new HumanDecision(command.decisionId(), command.reviewEventId(), command.outcome(),
                command.reviewerId(), command.reason().trim(), true);
    }

    private void prepareSubmission(Exchange exchange) {
        var message = exchange.getMessage();
        HumanDecision command = validate(new HumanDecision(message.getHeader("decisionId", String.class),
                message.getHeader("reviewEventId", String.class), message.getHeader("outcome", String.class),
                message.getHeader("reviewerId", String.class), message.getHeader("reason", String.class),
                Boolean.TRUE.equals(message.getHeader("confirmed", Boolean.class))));
        exchange.setProperty("humanCommand", command);
        message.removeHeaders("*");
        parameters(exchange);
    }

    private void prepareIncoming(Exchange exchange) {
        try {
            var payload = mapper.readTree(exchange.getMessage().getBody(String.class));
            if (payload == null || !payload.path("confirmed").isBoolean() || !payload.path("confirmed").asBoolean()) {
                throw new IllegalArgumentException("Explicit boolean confirmation is required");
            }
            HumanDecision command = validate(mapper.treeToValue(payload, HumanDecision.class));
            exchange.setProperty("humanCommand", command);
            exchange.setProperty("humanKey", command.reviewEventId());
            exchange.setProperty("humanSubmittedAt", Instant.now().toString());
            parameters(exchange);
        } catch (Exception error) {
            exchange.setProperty("humanRejectCode", "INVALID_HUMAN_DECISION");
        }
    }

    private void parameters(Exchange exchange) {
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        exchange.getMessage().setHeader("decisionId", command.decisionId());
        exchange.getMessage().setHeader("reviewEventId", command.reviewEventId());
        exchange.getMessage().setHeader("outcome", command.outcome());
        exchange.getMessage().setHeader("reviewerId", command.reviewerId());
        exchange.getMessage().setHeader("reason", command.reason());
        exchange.getMessage().setHeader("submittedAt", exchange.getProperty("humanSubmittedAt"));
    }

    private boolean sameCommand(HumanDecision command, Map<?, ?> stored) {
        return command.reviewEventId().equals(stored.get("reviewEventId"))
                && command.outcome().equals(stored.get("outcome"))
                && command.reviewerId().equals(stored.get("reviewerId"))
                && command.reason().equals(stored.get("reason"));
    }

    private void submissionStatus(Exchange exchange) {
        Map<?, ?> stored = exchange.getMessage().getBody(Map.class);
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        if (Boolean.TRUE.equals(stored.get("found"))) {
            if (!sameCommand(command, stored)) {
                throw new IllegalArgumentException("decisionId already belongs to a different submission");
            }
            exchange.setProperty("humanSubmit", "PENDING".equals(stored.get("status")));
        } else {
            exchange.setProperty("humanSubmit", true);
        }
    }

    private void checkOpenReview(Exchange exchange) {
        Map<?, ?> review = exchange.getMessage().getBody(Map.class);
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        if (!Boolean.TRUE.equals(review.get("found"))
                || (review.get("resolutionDecisionId") != null && !command.decisionId().equals(review.get("resolutionDecisionId")))) {
            throw new IllegalArgumentException("The review must exist and be available for a human decision");
        }
        exchange.getMessage().setBody(exchange.getProperty("humanCommand", HumanDecision.class));
    }

    private void submissionAcknowledgment(Exchange exchange) {
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        exchange.getMessage().setBody(Map.of("decisionId", command.decisionId(),
                "reviewEventId", command.reviewEventId(), "status", "SUBMITTED"));
    }

    private void storedDecision(Exchange exchange) {
        Map<?, ?> stored = exchange.getMessage().getBody(Map.class);
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        if (!Boolean.TRUE.equals(stored.get("found")) || !sameCommand(command, stored)) {
            exchange.setProperty("humanRejectCode", "DECISION_ID_CONFLICT");
            return;
        }
        exchange.setProperty("humanCanRecord", true);
        exchange.setProperty("humanSubmittedAt", stored.get("submittedAt"));
        parameters(exchange);
        if ("PUBLISHED".equals(stored.get("status"))
                || ("REJECTED".equals(stored.get("status")) && stored.get("publishedAt") != null)) {
            exchange.setProperty("humanSkip", true);
        } else if ("REJECTED".equals(stored.get("status"))) {
            exchange.setProperty("humanRejectCode", stored.get("errorCode"));
        }
    }

    private void decisionReview(Exchange exchange) {
        Map<?, ?> review = exchange.getMessage().getBody(Map.class);
        if (!Boolean.TRUE.equals(review.get("found"))) {
            exchange.setProperty("humanRejectCode", "REVIEW_NOT_FOUND");
        } else {
            exchange.setProperty("humanReview", review);
        }
    }

    private void reviewClaimed(Exchange exchange) {
        if (!Integer.valueOf(1).equals(exchange.getMessage().getHeader(JdbcConstants.JDBC_UPDATE_COUNT, Integer.class))) {
            exchange.setProperty("humanRejectCode", "REVIEW_ALREADY_CLAIMED");
        }
    }

    private void finalDecision(Exchange exchange) {
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        Map<?, ?> review = exchange.getProperty("humanReview", Map.class);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("eventType", "HUMAN_DECISION");
        result.put("eventId", command.decisionId());
        result.put("decisionId", command.decisionId());
        result.put("reviewEventId", command.reviewEventId());
        result.put("claimId", review.get("claimId"));
        result.put("correlationId", review.get("correlationId"));
        result.put("outcome", command.outcome());
        result.put("reasonCodes", List.of("APPROVED".equals(command.outcome()) ? "HUMAN_APPROVED" : "HUMAN_DENIED"));
        result.put("decisionSource", "HUMAN");
        result.put("reviewerId", command.reviewerId());
        result.put("reason", command.reason());
        result.put("confirmed", true);
        result.put("decidedAt", exchange.getProperty("humanSubmittedAt"));
        result.put("completedAt", exchange.getProperty("humanSubmittedAt"));
        exchange.getMessage().setBody(result);
    }

    private void rejection(Exchange exchange) {
        HumanDecision command = exchange.getProperty("humanCommand", HumanDecision.class);
        Map<String, Object> failure = new LinkedHashMap<>();
        failure.put("eventType", "HUMAN_DECISION_REJECTED");
        failure.put("eventId", command == null ? null : command.decisionId());
        failure.put("reviewEventId", command == null ? null : command.reviewEventId());
        failure.put("errorCode", "HUMAN_DECISION_REJECTED");
        failure.put("errorDetail", exchange.getProperty("humanRejectCode"));
        failure.put("stage", "HUMAN_REVIEW");
        exchange.getMessage().setBody(failure);
    }

    private void terminalParameters(Exchange exchange, String status) {
        exchange.getMessage().removeHeaders("*");
        parameters(exchange);
        exchange.getMessage().setHeader("terminalStatus", status);
        exchange.getMessage().setHeader("publishedAt", Instant.now().toString());
    }

    private void projectionParameters(Exchange exchange) {
        try {
            readProjectionParameters(exchange);
        } catch (IllegalArgumentException | ClassCastException | DateTimeException | NullPointerException error) {
            throw new InvalidReviewEventException();
        }
    }

    private void readProjectionParameters(Exchange exchange) {
        Map<?, ?> event = exchange.getMessage().getBody(Map.class);
        HumanDecision command = validate(new HumanDecision((String) event.get("decisionId"),
                (String) event.get("reviewEventId"), (String) event.get("outcome"),
                (String) event.get("reviewerId"), (String) event.get("reason"), Boolean.TRUE.equals(event.get("confirmed"))));
        String decidedAt = (String) event.get("decidedAt");
        Instant.parse(decidedAt);
        if (!command.decisionId().equals(event.get("eventId"))
                || !Identifiers.valid((String) event.get("claimId")) || !Identifiers.valid((String) event.get("correlationId"))) {
            throw new IllegalArgumentException("Invalid human decision context");
        }
        exchange.setProperty("humanCommand", command);
        exchange.setProperty("humanSubmittedAt", decidedAt);
        parameters(exchange);
        exchange.getMessage().setHeader("publishedAt", decidedAt);
        exchange.getMessage().setHeader("claimId", event.get("claimId"));
        exchange.getMessage().setHeader("correlationId", event.get("correlationId"));
    }
}
