/**
 * Unit test for the Hello service implementation
 */
package org.apache.camel.springboot.example;


import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class HelloPortImplTest {

    @Test
    public void testSayHello() {
        HelloPortImpl helloPort = new HelloPortImpl();
        String result = helloPort.sayHello("Test");

        assertNotNull(result, "Response should not be null");
        assertEquals("Hello, Welcome to CXF Spring boot Test!!!", result);
        assertTrue( result.contains("Test"), "Response should contain the name");
    }
}
