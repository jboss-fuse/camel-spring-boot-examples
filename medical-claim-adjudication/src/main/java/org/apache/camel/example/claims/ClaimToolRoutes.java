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

import org.apache.camel.ExchangePattern;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.dataformat.JsonLibrary;
import org.springframework.stereotype.Component;

@Component
public class ClaimToolRoutes extends RouteBuilder {
    private final ClaimMessages messages;

    public ClaimToolRoutes(ClaimMessages messages) {
        this.messages = messages;
    }

    @Override
    public void configure() {
        // Tool errors must reach the AI caller; they are not Kafka business events.
        errorHandler(noErrorHandler());

        from("ai-tool:get_claim_details?tags={{claims.ai.tool-tags}}"
                + "&description=Find a claim and its member reference by claim ID"
                + "&parameter.claimId=string&parameter.claimId.required=true&readOnlyHint=true")
            .routeId("claim-details-tool").startupOrder(20)
            .process(messages::startTool)
            .to(ExchangePattern.InOut, "direct:lookupClaim")
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class)
            .process(messages::finishTool);

        from("ai-tool:get_member_coverage?tags={{claims.ai.tool-tags}}"
                + "&description=Find active coverage, covered procedure, currency and per-claim limit for a member"
                + "&parameter.memberId=string&parameter.memberId.required=true&readOnlyHint=true")
            .routeId("member-coverage-tool").startupOrder(21)
            .process(messages::startTool)
            .to(ExchangePattern.InOut, "direct:lookupCoverage")
            .marshal().json(JsonLibrary.Jackson)
            .convertBodyTo(String.class)
            .process(messages::finishTool);

        from("direct:lookupClaim").routeId("claim-lookup").startupOrder(10)
            .validate(exchange -> Identifiers.valid(exchange.getMessage().getHeader("claimId")))
            .setBody(constant("""
                    SELECT claim_id AS "claimId", member_id AS "memberId",
                           procedure_code AS "procedureCode", billed_amount AS "billedAmount",
                           currency AS "currency" FROM claims WHERE claim_id = :?claimId
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(messages::lookupResult);

        from("direct:lookupCoverage").routeId("coverage-lookup").startupOrder(11)
            .validate(exchange -> Identifiers.valid(exchange.getMessage().getHeader("memberId")))
            .setBody(constant("""
                    SELECT member_id AS "memberId", active AS "active",
                           covered_procedure AS "coveredProcedure", claim_limit AS "claimLimit",
                           currency AS "currency", policy_version AS "policyVersion"
                    FROM coverage WHERE member_id = :?memberId
                    """))
            .to("{{claims.jdbc.endpoint}}")
            .process(messages::lookupResult);
    }
}
