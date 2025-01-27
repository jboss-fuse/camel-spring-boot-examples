package org.apache.camel.example.springboot;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.RestAssured;
import io.restassured.config.LogConfig;
import io.restassured.config.ObjectMapperConfig;
import io.restassured.filter.log.LogDetail;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.example.springboot.mapper.ExpenseMapper;
import org.apache.camel.example.springboot.model.Expense;
import org.apache.camel.example.springboot.repository.ExpenseRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.util.Random;

import static io.restassured.RestAssured.given;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ExpenseApiTest {

    private static final String CONSULTANT_USER = "rfaraujo";
    private static final String CONSULTANT_PASSWORD = "Barcelona";

    private static final String SUPERVISOR_USER = "rrios";
    private static final String SUPERVISOR_PASSWORD = "Palmeiras";

    private static final String EXPENSES_API_CLIENT_ID = "expenses-api";
    private static final String EXPENSES_API_CLIENT_SECRET = "YIQvHh3ny8T7thPu3HKgJXX3VvEhlxY6";

    private final ObjectMapper mapper = new ObjectMapper();


    private final Random random = new Random();

    @Autowired
    private ExpenseRepository expenseRepository;

    private ExpenseMapper expenseMapper = ExpenseMapper.INSTANCE;


    static KeycloakContainer keycloak = new KeycloakContainer()
            .withRealmImportFile("keycloak/expense-realm.json")
            .withAdminUsername("admin")
            .withAdminPassword("admin");

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void initialize(DynamicPropertyRegistry registry) {
        registry.add("keycloak.host", keycloak::getHost);
        registry.add("keycloak.port", keycloak::getHttpPort);
    }

    @BeforeAll
    static void beforeAll() {
        keycloak.start();
        RestAssured.config = RestAssured.config.objectMapperConfig(ObjectMapperConfig.objectMapperConfig());

        RestAssured.config = RestAssured.config()
                .logConfig(LogConfig.logConfig()
                        .enableLoggingOfRequestAndResponseIfValidationFails(LogDetail.ALL)
                        .enablePrettyPrinting(true));

        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
    }

    @AfterAll
    static void afterAll() {
        keycloak.stop();
    }

    @Test
    void shouldGetPublicURI() {

        given()
                .accept(ContentType.JSON)
                .baseUri("http://localhost:"+port+"/api/v1")
                .when()
                .get("/company")
              .then()
                .body("message", equalTo("We take pride in the work you do!"));
    }


    @Test
    void shouldGetAllExpenses() {

        given()
            .accept(ContentType.JSON)
            .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
                .baseUri("http://localhost:"+port+"/api/v1")
        .when()
            .get("/expense")
        .then()
            .assertThat()
                .statusCode(OK.value())
            .body("size()", equalTo((int) expenseRepository.count()));
    }


    @Test
    void shouldGetExpenseById() throws JsonProcessingException {
        long expenseId = new Random().nextLong((long) expenseRepository.count() - 1) + 1;

        Expense expense = expenseRepository.getReferenceById(expenseId);
        expenseRepository.flush();
        ExpenseDTO expernseDTO = expenseMapper.toDTO(expense);

        String expectedJson = mapper.writeValueAsString(expernseDTO);

        String response = given()
            .accept(ContentType.JSON)
            .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
            .baseUri("http://localhost:"+port+"/api/v1")
        .when()
            .get("/expense/{expenseId}", expenseId)
        .then()
            .assertThat()
            .statusCode(OK.value())
            .extract()
            .response().asString();
        assertThatJson(response).isEqualTo(expectedJson);
    }


    @Test
    void shouldSaveExpense() throws IOException {

        ExpenseDTO expense =  ExpenseTestUtils.createExpenses("Office Supplies", "Expenses for office supplies");
        String expenseJson = mapper.writeValueAsString(expense);

        String response =
                given()
                    .accept(ContentType.JSON)
                    .contentType(ContentType.JSON)
                    .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
                    .baseUri("http://localhost:"+port+"/api/v1")
                    .body(expenseJson)
                .when()
                    .post("/expense" )
                .then()
                    .assertThat()
                    .statusCode(CREATED.value())
                    .extract()
                    .response().asString();

        ExpenseDTO expenseDTO = mapper.readValue(response, ExpenseDTO.class);
        Expense expenseSaved = expenseRepository.findById(expenseDTO.getId()).orElseThrow(()->new RuntimeException("expense not saved!"));
        ExpenseTestUtils.compareExpenses(expenseDTO, expenseSaved);
    }

    @Test
    void shouldApproveExpense() throws IOException {
        ExpenseDTO expense =  ExpenseTestUtils.createExpenses("Meals week 34", "Expenses for meals  week 34");
        String expenseJson = mapper.writeValueAsString(expense);
        String response =
                given()
                        .accept(ContentType.JSON)
                        .contentType(ContentType.JSON)
                        .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
                        .baseUri("http://localhost:"+port+"/api/v1")
                        .body(expenseJson)
                .when()
                        .post("/expense" )
                .then()
                        .assertThat()
                        .statusCode(CREATED.value())
                        .extract()
                        .response().asString();

        ExpenseDTO expenseDTOResponse = mapper.readValue(response, ExpenseDTO.class);

        String approvalResponse =
                given()
                        .accept(ContentType.JSON)
                        .contentType(ContentType.JSON)
                        .header(AUTHORIZATION,BEARER.getValue() + " " + token(SUPERVISOR_USER, SUPERVISOR_PASSWORD))
                        .baseUri("http://localhost:"+port+"/api/v1")
                        .body(expenseJson)
                .when()
                        .put("/expense/{id}/approve", expenseDTOResponse.getId() )
                .then()
                        .assertThat()
                        .statusCode(OK.value())
                        .extract()
                        .response().asString();

        ExpenseDTO expenseDTO = mapper.readValue(approvalResponse, ExpenseDTO.class);
        Expense expenseSaved = expenseRepository.findById(expenseDTO.getId()).orElseThrow(()->new RuntimeException("expense not saved!"));
        ExpenseTestUtils.compareExpenses(expenseDTO, expenseSaved);

    }


    @Test
    void shouldGetForbiddenWhenTryToApproveExpense() throws IOException {
        ExpenseDTO expense =  ExpenseTestUtils.createExpenses("Travel to Brno Costs", "Expenses to Brno Costs");
        String expenseJson = mapper.writeValueAsString(expense);
        String response =
                given()
                        .accept(ContentType.JSON)
                        .contentType(ContentType.JSON)
                        .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
                        .baseUri("http://localhost:"+port+"/api/v1")
                        .body(expenseJson)
                .when()
                        .post("/expense" )
                .then()
                        .assertThat()
                        .statusCode(CREATED.value())
                        .extract()
                        .response().asString();

        ExpenseDTO expenseDTOResponse = mapper.readValue(response, ExpenseDTO.class);

        String approvalResponse =
                given()
                        .accept(ContentType.JSON)
                        .contentType(ContentType.JSON)
                        .header(AUTHORIZATION,BEARER.getValue() + " " + token(CONSULTANT_USER, CONSULTANT_PASSWORD))
                        .baseUri("http://localhost:"+port+"/api/v1")
                        .body(expenseJson)
                .when()
                        .put("/expense/{id}/approve", expenseDTOResponse.getId())
                .then()
                        .assertThat()
                        .statusCode(FORBIDDEN.value())
                        .extract()
                        .response().asString();

        Expense expenseSaved = expenseRepository.findById(expenseDTOResponse.getId()).orElseThrow(()->new RuntimeException("expense not saved!"));
        assertThat(expenseSaved.getApproval()).isNull();
    }


    private String token(String username, String password) {
        String baseUri = "http://"+keycloak.getHost()+":"+keycloak.getHttpPort()+"/realms/expenses/";
        String path = "/protocol/openid-connect/token";
        String  fullURI = baseUri + path;

        ExtractableResponse<Response> response =
            given()
                //.basic("expenses-api", "YIQvHh3ny8T7thPu3HKgJXX3VvEhlxY6")
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .baseUri(baseUri)
                .formParam(GRANT_TYPE, AuthorizationGrantType.PASSWORD.getValue())
                .formParam(CLIENT_ID, EXPENSES_API_CLIENT_ID)
                .formParam(CLIENT_SECRET, EXPENSES_API_CLIENT_SECRET)
                .formParam(USERNAME, username)
                .formParam(PASSWORD, password)
                .post(path)
            .then()
                .extract();

        String accessToken = response.response().jsonPath()
                .getString(ACCESS_TOKEN);

        return accessToken;
    }
}