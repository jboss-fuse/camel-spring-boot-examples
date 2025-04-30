package org.apache.camel.springboot.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.*;


import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SampleWsApplicationIntegrationTest {

    @LocalServerPort
    private int serverPort;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private TestRestTemplate restTemplate;


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

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_XML);
        // Check WSDL if SOAPAction is needed, e.g., headers.add("SOAPAction", "\"\"");

        HttpEntity<String> entity = new HttpEntity<>(soapRequest, headers);

        String serviceUrl = "http://localhost:" + serverPort + "/service/hello";

        ResponseEntity<String> response = restTemplate.postForEntity(serviceUrl, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        // More specific assertion on the response content
        assertThat(response.getBody()).contains("<return>Hello, Welcome to CXF Spring boot " + name + "!!!</return>");
        assertThat(response.getBody()).contains("sayHelloResponse"); // Check for response element
    }

    @Test
    void testWsdlAvailability() {
        String wsdlUrl = "http://localhost:" + serverPort + "/service/hello?wsdl";
        ResponseEntity<String> response = restTemplate.getForEntity(wsdlUrl, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).contains("<wsdl:definitions");
        assertThat(response.getBody()).contains("HelloService"); // Check for service name in WSDL
        assertThat(response.getBody()).contains("HelloPort");    // Check for port name in WSDL
    }

    @Test
    void testHealthEndpoint() {
        String healthUrl = "http://localhost:" + managementPort + "/actuator/health";
        ResponseEntity<String> response = restTemplate.getForEntity(healthUrl, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }
}