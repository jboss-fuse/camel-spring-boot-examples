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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import com.openai.models.chat.completions.ChatCompletion;
import org.apache.camel.Exchange;
import org.apache.camel.component.openai.OpenAIConstants;
import org.apache.camel.component.openai.OpenAIEndpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

/** Provider requests and local validation use the same portable decision schema. */
@Component
public class RecommendationOutput {
    private static final Logger LOG = LoggerFactory.getLogger(RecommendationOutput.class);
    private static final Pattern FENCE = Pattern.compile("\\A```(?:json)?\\R([\\s\\S]*?)\\R```\\z");
    private static final Set<String> FIELDS = Set.of("claimId", "outcome", "reasonCodes", "policyVersion");
    private final ObjectMapper mapper = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final Schema schema;
    private final Map<String, Object> responseFormat;
    private final boolean compatibility;
    private final int maxBytes;

    public RecommendationOutput(@Value("${claims.ai.output-policy}") String policy,
                                @Value("${claims.ai.max-response-bytes}") int maxBytes,
                                @Value("classpath:schemas/recommendation.json") Resource resource) throws Exception {
        if (!Set.of("compatibility", "schema").contains(policy) || maxBytes < 1) {
            throw new IllegalArgumentException("Use output-policy compatibility or schema and a positive response limit");
        }
        this.compatibility = "compatibility".equals(policy);
        this.maxBytes = maxBytes;
        String text = resource.getContentAsString(StandardCharsets.UTF_8);
        schema = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12).getSchema(text);
        Map<?, ?> definition = mapper.readValue(text, Map.class);
        responseFormat = Map.of("type", "json_schema", "json_schema",
                Map.of("name", "claim_recommendation", "strict", true, "schema", definition));
    }

    public void configure(OpenAIEndpoint endpoint) {
        // Camel 4.22.1's jsonSchema option omits strict=true. Supply the complete wrapper.
        // No tools are registered on this endpoint, and errors never trigger an unconstrained fallback.
        if (!compatibility) {
            Map<String, Object> properties = new LinkedHashMap<>();
            if (endpoint.getConfiguration().getAdditionalBodyProperty() != null) {
                properties.putAll(endpoint.getConfiguration().getAdditionalBodyProperty());
            }
            properties.put("response_format", responseFormat);
            endpoint.getConfiguration().setAdditionalBodyProperty(properties);
        }
    }

    public void checkCompletion(Exchange exchange) {
        String finish = exchange.getMessage().getHeader(OpenAIConstants.FINISH_REASON, String.class);
        if (!"stop".equals(finish)) {
            throw new ClaimException("INVALID_AI_RESPONSE", "INCOMPLETE_AI_RESPONSE");
        }
        ChatCompletion response = exchange.getProperty(OpenAIConstants.RESPONSE, ChatCompletion.class);
        if (response == null || response.choices().size() != 1) {
            throw new ClaimException("INVALID_AI_RESPONSE", "INVALID_COMPLETION");
        }
        var choice = response.choices().get(0);
        // Check the stored response too: the component maps an absent/unknown finish reason to stop.
        if (!"stop".equals(choice._finishReason().asKnown().map(Object::toString).orElse(""))) {
            throw new ClaimException("INVALID_AI_RESPONSE", "INCOMPLETE_AI_RESPONSE");
        }
        var message = choice.message();
        if (message.refusal().isPresent()) {
            throw new ClaimException("INVALID_AI_RESPONSE", "AI_REFUSAL");
        }
        if (!message.toolCalls().orElse(java.util.List.of()).isEmpty()) {
            throw new ClaimException("INVALID_AI_RESPONSE", "UNEXPECTED_TOOL_CALL");
        }
    }

    public ClaimMessages.Recommendation read(Exchange exchange) {
        checkCompletion(exchange);
        String text = exchange.getMessage().getBody(String.class);
        if (text == null || text.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            throw new ClaimException("INVALID_AI_RESPONSE", "RESPONSE_SIZE_LIMIT");
        }
        text = text.strip();
        var fence = FENCE.matcher(text);
        if (compatibility && fence.matches()) {
            text = fence.group(1).strip();
            exchange.setProperty("claimResponseNormalized", true);
            LOG.warn("claim_response_normalized event={} policy=compatibility",
                    exchange.getProperty("claimEvent", ClaimEvent.class).eventId());
        }
        try {
            JsonNode node = mapper.readTree(text);
            if (node == null || !node.isObject()) {
                throw new ClaimException("INVALID_AI_RESPONSE", "INVALID_RECOMMENDATION_FIELDS");
            }
            var names = node.fieldNames();
            while (names.hasNext()) {
                if (!FIELDS.contains(names.next())) {
                    throw new ClaimException("INVALID_AI_RESPONSE", "UNEXPECTED_RESPONSE_FIELDS");
                }
            }
            // NetworkNT 3 parses with Jackson 3. Strict parsing above rejects duplicate/trailing tokens first.
            if (!schema.validate(text, InputFormat.JSON).isEmpty()) {
                throw new ClaimException("INVALID_AI_RESPONSE", "INVALID_RECOMMENDATION_FIELDS");
            }
            return mapper.treeToValue(node, ClaimMessages.Recommendation.class);
        } catch (ClaimException error) {
            throw error;
        } catch (Exception error) {
            // Never include model content or schema validation diagnostics in a public failure envelope.
            throw new ClaimException("INVALID_AI_RESPONSE", "INVALID_RESPONSE_JSON");
        }
    }
}
