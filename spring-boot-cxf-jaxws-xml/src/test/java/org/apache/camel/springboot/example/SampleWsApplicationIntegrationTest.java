package org.apache.camel.springboot.example;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.*;
import org.springframework.web.client.RestClient;


import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SampleWsApplicationIntegrationTest {

    @LocalServerPort
    private int serverPort;

    @LocalManagementPort
    private int managementPort;

    private RestClient restClient = RestClient.create();


    @Test
    void contextLoads() {
        // Basic test to ensure the application context loads successfully
    }

    @Test
    void testSayHelloSoapEndpoint() {
        String name = "IntegrationTest";
        String soapRequest = String.format(
                "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ser=\"http://service.ws.sample/\">" +
                        "   <soapenv:Header/>" +
                        "   <soapenv:Body>" +
                        "      <ser:sayHello>" +
                        "         <myname>%s</myname>" +
                        "      </ser:sayHello>" +
                        "   </soapenv:Body>" +
                        "</soapenv:Envelope>", name);

        String serviceUrl = "http://localhost:" + serverPort + "/service/hello";

        ResponseEntity<String> response = restClient.post()
                .uri(serviceUrl)
                .contentType(MediaType.TEXT_XML)
                .body(soapRequest)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        // More specific assertion on the response content
        assertThat(response.getBody()).contains("<return>Hello, Welcome to CXF Spring boot " + name + "!!!</return>");
        assertThat(response.getBody()).contains("sayHelloResponse"); // Check for response element
    }

    @Test
    void testWsdlAvailability() {
        String wsdlUrl = "http://localhost:" + serverPort + "/service/hello?wsdl";
        ResponseEntity<String> response = restClient.get()
                .uri(wsdlUrl)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).contains("<wsdl:definitions");
        assertThat(response.getBody()).contains("HelloService"); // Check for service name in WSDL
        assertThat(response.getBody()).contains("HelloPort");    // Check for port name in WSDL
    }

    @Test
    void testHealthEndpoint() {
        String healthUrl = "http://localhost:" + managementPort + "/actuator/health";
        ResponseEntity<String> response = restClient.get()
                .uri(healthUrl)
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }
}