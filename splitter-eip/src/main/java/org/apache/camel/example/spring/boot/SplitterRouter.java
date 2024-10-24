/*
 *
 *  * Licensed to the Apache Software Foundation (ASF) under one or more
 *  * contributor license agreements.  See the NOTICE file distributed with
 *  * this work for additional information regarding copyright ownership.
 *  * The ASF licenses this file to You under the Apache License, Version 2.0
 *  * (the "License"); you may not use this file except in compliance with
 *  * the License.  You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.apache.camel.example.spring.boot;

import org.apache.camel.builder.AggregationStrategies;
import org.apache.camel.builder.RouteBuilder;

import org.springframework.stereotype.Component;

@Component
public class SplitterRouter extends RouteBuilder {
	@Override
	public void configure() throws Exception {

		// @formatter:off
		// Example 1 : Simple splitter
		from("direct:splitter")
				// body is of type java.lang.Iterable, java.lang.String or Array
				.split(body())
				.log("${body}")
				.to("mock:a");

		// Example 2 : Splitter with subsequent aggregation
		from("direct:split-aggregate")
					.split(body(), ((oldExchange, newExchange) -> {
						if (oldExchange == null) {
							// this is the first time so no existing aggregated exchange
							return newExchange;
						}

						String body = newExchange.getIn().getBody(String.class);
						String existing = oldExchange.getIn().getBody(String.class);

						oldExchange.getIn().setBody(existing + "+" + body);
						return oldExchange;
					}))
				// Transform after aggregation
				.bean(MyMessageTransformer.class)
				.log("split ${body}")
				.to("mock:b")
				.end()
			.log("aggregated ${body}")
			.to("mock:c");

		// Example 3 : Splitter with subsequent aggregation using POJO bean instead of AggregationStrategy implementation
		from("direct:split-aggregate-bean")
				// Aggregation with POJO, no tight coupling to Camel API - better for unit testing
					.split(body(), AggregationStrategies.bean(AggregationStrategyPojo.class))
					// Transformation after aggregation
					.bean(MyMessageTransformer.class)
					.log("bean split ${body}")
					.to("mock:d")
				.end()
			.log("bean aggregated ${body}")
			.to("mock:e");

		// Example 4 : Splitter with subsequent aggregation failing on exception
		from("direct:split-aggregate-stop-on-exception")
				.split(body(), AggregationStrategies.bean(AggregationStrategyPojo.class))
						// stop processing if exception occurred during process of splitting
						.stopOnException()
						.bean(MyMessageTransformer.class)
					.log("${body}")
					.to("mock:f")
				.end()
			.log("never be there ${body}")
			.to("mock:g");

		// Example 5: Splitter with subsequent aggregation on failing on aggregation exception
		from("direct:split-aggregate-stop-on-aggregation-exception")
				// Continuing route processing on exception
				.onException(IllegalArgumentException.class).continued(true).end()
				.split(body(), ((oldExchange, newExchange) -> {
						if (oldExchange == null) {
							// this is the first time so no existing aggregated exchange
							return newExchange;
						}

						String body = newExchange.getIn().getBody(String.class);
						String existing = oldExchange.getIn().getBody(String.class);
						if (body.equals("E")){
							throw new IllegalArgumentException("Error occurred during aggregation");
						}
						oldExchange.getIn().setBody(existing + "+" + body);
						return oldExchange;
					}))
					.bean(MyMessageTransformer.class)
				.log("processed even if there are errors: ${body}")
				.to("mock:h")
				.end()
			.log("reply with original body: ${body}")
			.to("mock:j");
		// @formatter:on

	}
}

