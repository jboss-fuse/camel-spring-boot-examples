/**
 * Integration test that verifies the web service is up and running
 */
package org.apache.camel.springboot.example;

import java.net.URL;

import javax.xml.namespace.QName;
import jakarta.xml.ws.Service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class HelloServiceIntegrationTest {

    @LocalServerPort
    private int port;

    @Test
    public void testSayHelloIntegration() throws Exception {
        URL wsdlURL = new URL("http://localhost:" + port + "/service/hello?wsdl");

        QName serviceName = new QName("http://service.ws.sample/", "HelloService");
        QName portName = new QName("http://service.ws.sample/", "HelloPort");

        Service service = Service.create(wsdlURL, serviceName);
        Hello hello = service.getPort(portName, Hello.class);

        assertNotNull(hello,"Service endpoint should not be null");

        String response = hello.sayHello("Integration");
        assertNotNull(response,"Response should not be null" );
        assertEquals("Hello, Welcome to CXF Spring boot Integration!!!", response);
    }
}
