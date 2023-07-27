package org.apache.camel.example.spring.boot;

import org.apache.camel.builder.RouteBuilder;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

@Component
public class RestRouter extends RouteBuilder {
	@Override
	public void configure() throws Exception {

		restConfiguration().component("servlet");

		rest().post("/split-on-log")
				.consumes(MediaType.TEXT_PLAIN_VALUE)
				.produces(MediaType.TEXT_PLAIN_VALUE)
				.to("direct:send-to-splitter");

		from("direct:send-to-splitter")
				.setHeader("recipient", constant("splitter"))
				.choice()
					.when(simple("${header.convert-to} == 'array'"))
						.to("direct:to-array-and-send")
					.otherwise()
						.to("direct:to-string-and-send");

		rest().post("/split-aggregate-on-log")
				.consumes(MediaType.TEXT_PLAIN_VALUE)
				.produces(MediaType.TEXT_PLAIN_VALUE)
				.to("direct:send-to-split-aggregate");

		from("direct:send-to-split-aggregate")
				.choice()
					.when(simple("${header.use-bean} == 'true'"))
						.setHeader("recipient", constant("split-aggregate-bean"))
					.otherwise()
						.setHeader("recipient", constant("split-aggregate"))
				.end()
				.to("direct:to-string-and-send");

		rest().post("/handle-error")
				.consumes(MediaType.TEXT_PLAIN_VALUE)
				.produces(MediaType.TEXT_PLAIN_VALUE)
				.to("direct:send-error");

		from("direct:send-error")
				.choice()
					.when(simple("${header.stop-on-error} == 'false'"))
						.setHeader("recipient", constant("split-aggregate-stop-on-aggregation-exception"))
					.otherwise()
						.setHeader("recipient", constant("split-aggregate-stop-on-exception"))
				.end()
				.to("direct:to-string-and-send");

		// common
		from("direct:to-array-and-send")
				.log("convert to array")
				.process(exchange -> {
					exchange.getIn().setBody(exchange.getIn().getBody(String.class).split(","));
				}).toD("direct:${header.recipient}");

		from("direct:to-string-and-send")
				.convertBodyTo(String.class)
				.toD("direct:${header.recipient}");
	}
}
