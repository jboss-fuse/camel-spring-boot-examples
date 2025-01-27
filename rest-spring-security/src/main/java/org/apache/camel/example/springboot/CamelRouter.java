package org.apache.camel.example.springboot;

import org.apache.camel.CamelAuthorizationException;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.example.springboot.dto.CompanyMessageDTO;
import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.model.rest.RestBindingMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import static org.apache.camel.Exchange.HTTP_RESPONSE_CODE;
import static org.apache.camel.model.rest.RestParamType.path;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Component
public class CamelRouter extends RouteBuilder {

    @Autowired
    private Environment env;

    @Value("${camel.servlet.mapping.context-path}")
    private String contextPath;


    @Override
    public void configure() throws Exception {

        onException(CamelAuthorizationException.class)
                .handled(true)
                .log(LoggingLevel.ERROR,"Exception occurred while processing request: ${exception.message}")
                .log(LoggingLevel.DEBUG,"${exception.stacktrace}")
                .setHeader(HTTP_RESPONSE_CODE, constant(FORBIDDEN.value()));


        restConfiguration()
                .component("platform-http")
                .bindingMode(RestBindingMode.auto)
                .dataFormatProperty("prettyPrint", "true")
                .inlineRoutes(true)
                .enableNoContentResponse(false)
                .enableCORS(false)
                .host(env.getProperty("server.address", "localhost"))
                .port(env.getProperty("server.port", "8081"))
                .contextPath(contextPath.substring(0, contextPath.length() - 2))
                // turn on openapi api-doc
                .apiContextPath("/api-doc")
                .apiProperty("api.title", "Expense API")
                .apiProperty("api.version", "1.0.0");



        rest("/v1")
                .consumes(APPLICATION_JSON_VALUE)
                .produces(APPLICATION_JSON_VALUE)


                .securityDefinitions()
       // bearerToken(String key, String description, String bearerFormat) {
                .bearerToken("jwt", "OpenIdConnect JWT Bearer Token", "JWT")
                //.openIdConnect("openId", "{{spring.security.oauth2.resourceserver.jwt.issuer-uri}}")
                .end()


                .post("/expense")
                    .type(ExpenseDTO.class)
                    .outType(ExpenseDTO.class)
                    .security("jwt")
                    .consumes(APPLICATION_JSON_VALUE)
                    .produces(APPLICATION_JSON_VALUE)

                    .description("create an expense")
                    .outType(ExpenseDTO.class)
                    .responseMessage()
                    .code(OK.value())
                    .message("Expense successfully created")
                    .endResponseMessage()
                    .security("jwt")
                .routeId("create-expense-rest")
                .to("direct:create-expense")

                // Public URL
                .get("/company")
                .consumes(APPLICATION_JSON_VALUE)
                .produces(APPLICATION_JSON_VALUE)

                .responseMessage()
                .code(OK.value())
                .message("Company Motto")
                .endResponseMessage()
                .description("The public API is available for everyone.")
                .routeId("getPublic")
                .outType(CompanyMessageDTO.class)
                .to("direct:public")

                //READ ALL
                .get("/expense")
                    .description("Find all expenses").outType(ExpenseDTO[].class)
                    .description("Method to get all expenses")
                .security("jwt")

                .responseMessage()
                        .code(OK.value())
                        .message("All expenses successfully returned")
                    .endResponseMessage()
                    .security("openid")
                    .routeId("getAll")
                    .to("direct:readAll")

                //READ
                .get("/expense/{id}")
                .description("Method to get the expense searching by the provided id")
                    .security("jwt")
                    .routeId("getById")
                    .outType(ExpenseDTO.class)
                    .param().name("id").type(path).description("The ID of the expense").dataType("integer").endParam()
                    .responseMessage()
                    .code(OK.value())
                    .message("User successfully returned").endResponseMessage()
                    .to("direct:read")

                //APPROVE
                .put("/expense/{id}/approve")
                    .description("Method to approve the expense identified by the provided id")
                    .security("jwt")
                    .routeId("getById")
                    .outType(ExpenseDTO.class)

                    .param().name("id").type(path).description("The ID of the expense").dataType("integer").endParam()
                    .responseMessage().code(OK.value())
                    .message("User successfully returned").endResponseMessage()
                    .to("direct:approve-expense")

                .put("/expense/{id}/reject")
                .description("Method to reject the expense identified by the provided id")
                    .security("jwt")
                    .routeId("getById")
                    .outType(ExpenseDTO.class)

                    .param().name("id").type(path).description("The ID of the expense").dataType("integer").endParam()
                    .responseMessage().code(OK.value())
                    .message("User successfully returned").endResponseMessage()
                    .to("direct:reject-expense");


                from("direct:public")
                    .routeId("public")
                    .process(exchange ->
                                exchange.getMessage()
                                        .setBody(CompanyMessageDTO.builder().message("We take pride in the work you do!").build()));
                        //.marshal().json(JsonLibrary.Jackson);

                //READ ALL
                from("direct:readAll")
                    .routeId("readAll")
                        .policy("consultantPolicy")
                        .to("bean:expenseService?method=getExpenses");

                from("direct:read")
                    .routeId("read")
                        .policy("consultantPolicy")
                        .to("bean:expenseService?method=getExpense(${header.id})");


                from("direct:create-expense")
                    .routeId("create-expense-route")
                        .policy("consultantPolicy")
                        .setHeader(HTTP_RESPONSE_CODE,constant(CREATED.value()))// simple(HTTP_CREATED))
                        .to("bean:expenseService?method=createExpense");

                from("direct:approve-expense")
                    .routeId("approve-expense-route")
                    .policy("supervisorPolicy")
                    .to("bean:expenseService?method=approveExpense(${header.id})");


                from("direct:reject-expense")
                    .routeId("reject-expense-route")
                    .policy("supervisorPolicy")
                    .to("bean:expenseService?method=rejectExpense(${header.id})");

    }
}

