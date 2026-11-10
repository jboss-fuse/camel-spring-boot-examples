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

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.camel.ExchangePattern;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.kafka.KafkaConstants;
import org.apache.camel.component.openai.OpenAIEndpoint;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ClaimRoutes extends RouteBuilder {
    private final ClaimMessages messages;
    private final RecommendationOutput output;
    private final int retries;
    private final long retryDelay;

    public ClaimRoutes(ClaimMessages messages, RecommendationOutput output,
                       @Value("${claims.retry.maximum-redeliveries}") int retries,
                       @Value("${claims.retry.delay-ms}") long retryDelay) {
        this.messages = messages;
        this.output = output;
        this.retries = retries;
        this.retryDelay = retryDelay;
    }

    @Override
    public void configure() {
        OpenAIEndpoint finalEndpoint = getContext().getEndpoint("{{claims.ai.final-endpoint}}", OpenAIEndpoint.class);
        output.configure(finalEndpoint);
        errorHandler(deadLetterChannel("direct:claimFailure").deadLetterHandleNewException(false)
                .useOriginalMessage().maximumRedeliveries(retries).redeliveryDelay(retryDelay)
                .logExhausted(false).logStackTrace(false));
        onException(ClaimCommitException.class)
                .maximumRedeliveries(0).handled(false)
                .process(messages::commitFailed);
        onException(ClaimException.class, JsonProcessingException.class)
                .maximumRedeliveries(0);

        from("{{claims.kafka.input-endpoint}}").routeId("claims-ingestion").startupOrder(100)
            .setProperty("claimStage", constant("INPUT"))
            .process(messages::captureTransport)
            .unmarshal().json(JsonLibrary.Jackson, ClaimEvent.class)
            .process(messages::prepare)
            .removeHeaders("*")
            .to(ExchangePattern.InOut, "direct:adjudicate")
            .process(messages::commit);

        from("direct:adjudicate").routeId("claims-adjudication").startupOrder(50)
            .setProperty("claimStage", constant("VERIFY"))
            .setHeader("claimId", simple("${exchangeProperty.claimEvent.claimId}"))
            .to(ExchangePattern.InOut, "direct:lookupClaim")
            .process(messages::rememberClaim)
            .choice()
                .when(header("memberId").isNotNull())
                    .to(ExchangePattern.InOut, "direct:lookupCoverage")
            .end()
            .process(messages::finalPrompt)
            .setProperty("claimStage", constant("AI"))
            .to(finalEndpoint).id("invoke-final-ai")
            .process(messages::readRecommendation)
            // Recheck the evidence after inference, without holding a database transaction open.
            .setProperty("claimStage", constant("VERIFY"))
            .to(ExchangePattern.InOut, "direct:lookupClaim")
            .process(messages::rememberClaim)
            .choice()
                .when(header("memberId").isNotNull())
                    .to(ExchangePattern.InOut, "direct:lookupCoverage")
            .end()
            .process(messages::validateDecision)
            .setProperty("claimStage", constant("PUBLISH"))
            .to("direct:publishDecision");

        from("direct:publishDecision").routeId("claims-publication").startupOrder(30)
            .errorHandler(noErrorHandler())
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class)
            .removeHeaders("*")
            .setHeader(KafkaConstants.KEY, simple("${exchangeProperty.claimEvent.claimId}"))
            .to("{{claims.kafka.results-endpoint}}")
            .process(messages::published);

        from("direct:claimFailure").routeId("claims-failure").startupOrder(31)
            .errorHandler(noErrorHandler())
            .process(messages::failure)
            .setProperty("failureClaimId", simple("${body[claimId]}"))
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class)
            .removeHeaders("*")
            .setHeader(KafkaConstants.KEY, exchangeProperty("failureClaimId"))
            .to("{{claims.kafka.failures-endpoint}}")
            .process(messages::commit);
    }
}
