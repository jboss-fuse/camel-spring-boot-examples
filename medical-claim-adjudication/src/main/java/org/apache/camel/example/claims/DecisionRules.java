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

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

/** Ordered demo policy: generates the prompt and validates the recommendation. */
public final class DecisionRules {
    private record Rule(String condition, BiPredicate<Map<?, ?>, Map<?, ?>> matches,
                        String outcome, List<String> reasons) {
    }

    private static final List<Rule> RULES = List.of(
            new Rule("claim.found=false", (c, v) -> !Boolean.TRUE.equals(c.get("found")),
                    "MANUAL_REVIEW", List.of("MISSING_CLAIM")),
            new Rule("coverage.found=false", (c, v) -> !Boolean.TRUE.equals(v.get("found")),
                    "MANUAL_REVIEW", List.of("MISSING_COVERAGE")),
            new Rule("coverage.active=false", (c, v) -> !Boolean.TRUE.equals(v.get("active")),
                    "DENIED", List.of("INACTIVE_COVERAGE")),
            new Rule("claim.procedureCode and coverage.coveredProcedure differ as exact strings",
                    (c, v) -> !Objects.equals(c.get("procedureCode"), v.get("coveredProcedure")),
                    "DENIED", List.of("PROCEDURE_EXCLUDED")),
            new Rule("claim.currency and coverage.currency differ",
                    (c, v) -> !Objects.equals(c.get("currency"), v.get("currency")),
                    "MANUAL_REVIEW", List.of("CURRENCY_MISMATCH")),
            new Rule("claim.billedAmount is numerically greater than coverage.claimLimit",
                    (c, v) -> new BigDecimal(c.get("billedAmount").toString())
                            .compareTo(new BigDecimal(v.get("claimLimit").toString())) > 0,
                    "DENIED", List.of("LIMIT_EXCEEDED")),
            new Rule("otherwise", (c, v) -> true,
                    "APPROVED", List.of("ACTIVE_COVERAGE", "PROCEDURE_COVERED", "WITHIN_LIMIT")));

    private DecisionRules() {
    }

    public static ClaimMessages.Recommendation evaluate(String claimId, Map<?, ?> claim, Map<?, ?> coverage) {
        Rule rule = RULES.stream().filter(r -> r.matches().test(claim, coverage)).findFirst().orElseThrow();
        String policy = Boolean.TRUE.equals(claim.get("found")) && Boolean.TRUE.equals(coverage.get("found"))
                ? (String) coverage.get("policyVersion") : null;
        return new ClaimMessages.Recommendation(claimId, rule.outcome(), rule.reasons(), policy);
    }

    public static String prompt() {
        return RULES.stream().map(r -> "- " + r.condition() + ": " + r.outcome() + ", reasonCodes ["
                + r.reasons().stream().map(reason -> "\"" + reason + "\"").collect(Collectors.joining(",")) + "].")
                .collect(Collectors.joining("\n"));
    }
}
