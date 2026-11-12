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
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.ExchangePattern;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Builds the review view from confirmed automated and human Kafka results. */
@Component
public class ManualReviewRoutes extends RouteBuilder {
    private static final DateTimeFormatter TIMESTAMP = new DateTimeFormatterBuilder().appendInstant(9).toFormatter();
    private final ObjectMapper mapper = new ObjectMapper();
    private final ClaimMessages messages;
    private final int retries;
    private final long retryDelay;

    public ManualReviewRoutes(ClaimMessages messages,
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

        onException(InvalidReviewEventException.class, JsonProcessingException.class)
                .maximumRedeliveries(0).handled(true)
                .log("review_projection_skipped topic=${exchangeProperty.sourceTopic} partition=${exchangeProperty.sourcePartition} offset=${exchangeProperty.sourceOffset}")
                .process(messages::commit);

        from("{{claims.reviews.input-endpoint}}").routeId("manual-review-projection").startupOrder(90)
            .process(messages::captureTransport)
            .removeHeaders("*")
            .unmarshal().json(JsonLibrary.Jackson)
            .process(exchange -> {
                if (!(exchange.getMessage().getBody() instanceof Map)) {
                    throw new InvalidReviewEventException();
                }
            })
            .choice()
                .when(simple("${body[eventType]} == 'HUMAN_DECISION'"))
                    .to(ExchangePattern.InOut, "direct:projectHumanDecision")
                .when(simple("${body[outcome]} == 'MANUAL_REVIEW'"))
                    .process(this::reviewParameters)
                    // Replayed terminal events retain their event ID and must not add duplicate reviews.
                    .setBody(constant("""
                            INSERT INTO manual_reviews
                                (event_id, claim_id, correlation_id, reason_codes, completed_at, resolution_decision_id)
                            SELECT :?eventId, :?claimId, :?correlationId, :?reasonCodes, :?completedAt,
                                   (SELECT MIN(decision_id) FROM human_decisions
                                    WHERE review_event_id = :?eventId AND status = 'PUBLISHED')
                            WHERE NOT EXISTS (SELECT 1 FROM manual_reviews WHERE event_id = :?eventId)
                            """))
                    .to("{{claims.jdbc.endpoint}}")
            .end()
            .process(messages::commit);

        from("ai-tool:list_manual_reviews?tags={{claims.reviews.tool-tags}}"
                + "&description=List medical claim events awaiting human review, oldest first; returns reviews, limit and offset"
                + "&parameter.limit=integer&parameter.limit.description=Page size from 1 to 100; default 20"
                + "&parameter.offset=integer&parameter.offset.description=Nonnegative page offset; default 0"
                + "&readOnlyHint=true")
            .routeId("list-manual-reviews-tool").startupOrder(22)
            .errorHandler(noErrorHandler())
            .process(messages::startTool)
            .to(ExchangePattern.InOut, "direct:listManualReviews")
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class)
            .process(messages::finishTool);

        from("direct:listManualReviews").routeId("manual-review-list").startupOrder(12)
            .errorHandler(noErrorHandler())
            .process(this::pageParameters)
            .setBody(constant("""
                    SELECT event_id AS "eventId", claim_id AS "claimId", correlation_id AS "correlationId",
                           reason_codes AS "reasonCodes", completed_at AS "completedAt",
                           resolution_decision_id AS "decisionId",
                           CASE WHEN resolution_decision_id IS NULL THEN 'OPEN' ELSE 'PENDING' END AS "reviewStatus"
                    FROM manual_reviews r
                    WHERE NOT EXISTS (SELECT 1 FROM human_decisions d
                                      WHERE d.decision_id = r.resolution_decision_id
                                        AND d.review_event_id = r.event_id AND d.status = 'PUBLISHED')
                    ORDER BY CAST(completed_at AS TIMESTAMP WITH TIME ZONE), event_id
                    OFFSET :?offset ROWS FETCH NEXT :?limit ROWS ONLY
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(this::reviewPage);
    }

    private void reviewParameters(Exchange exchange) throws Exception {
        Map<?, ?> event = exchange.getMessage().getBody(Map.class);
        for (String name : List.of("eventId", "claimId", "correlationId")) {
            Object value = event.get(name);
            if (!(value instanceof String text) || !Identifiers.valid(text)) {
                throw new InvalidReviewEventException();
            }
            exchange.getMessage().setHeader(name, value);
        }
        Object reasons = event.get("reasonCodes");
        if (!(reasons instanceof List<?> list) || list.isEmpty()
                || list.stream().anyMatch(reason -> !(reason instanceof String))) {
            throw new InvalidReviewEventException();
        }
        String encoded = mapper.writeValueAsString(reasons);
        if (encoded.length() > 2000 || !(event.get("completedAt") instanceof String completedAt)) {
            throw new InvalidReviewEventException();
        }
        try {
            String timestamp = TIMESTAMP.format(Instant.parse(completedAt));
            if (timestamp.length() > 40) {
                throw new InvalidReviewEventException();
            }
            exchange.getMessage().setHeader("completedAt", timestamp);
        } catch (IllegalArgumentException | DateTimeException error) {
            throw new InvalidReviewEventException();
        }
        exchange.getMessage().setHeader("reasonCodes", encoded);
    }

    private void pageParameters(Exchange exchange) {
        Integer limit = exchange.getMessage().getHeader("limit", 20, Integer.class);
        Integer offset = exchange.getMessage().getHeader("offset", 0, Integer.class);
        if (limit == null || limit < 1 || limit > 100 || offset == null || offset < 0) {
            throw new IllegalArgumentException("limit must be 1 to 100 and offset must be nonnegative");
        }
        exchange.getMessage().setHeader("limit", limit);
        exchange.getMessage().setHeader("offset", offset);
    }

    private void reviewPage(Exchange exchange) throws Exception {
        List<?> reviews = exchange.getMessage().getBody(List.class);
        for (Object value : reviews) {
            @SuppressWarnings("unchecked")
            Map<String, Object> review = (Map<String, Object>) value;
            review.put("reasonCodes", mapper.readValue((String) review.get("reasonCodes"), List.class));
        }
        exchange.getMessage().setBody(Map.of("reviews", reviews,
                "limit", exchange.getMessage().getHeader("limit"),
                "offset", exchange.getMessage().getHeader("offset")));
    }
}
