/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.camel.springboot.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for HelloImpl class that implements the Hello web service.
 */
public class HelloServiceTest {

    private HelloImpl helloService;

    @BeforeEach
    public void setUp() {
        // Create a new instance of the service implementation before each test
        helloService = new HelloImpl();
    }

    @Test
    @DisplayName("Test sayHello with a standard name")
    public void testSayHelloWithName() {
        // Given a name
        String name = "John";

        // When saying hello
        String response = helloService.sayHello(name);

        // Then verify the response contains the name and welcome message
        assertNotNull(response, "Response should not be null");
        assertTrue(response.contains("John"), "Response should contain the provided name");
        assertTrue(response.contains("Hello"), "Response should contain a greeting");
        assertTrue(response.contains("Welcome to CXF Spring boot"), "Response should mention CXF Spring boot");
    }

    @ParameterizedTest
    @DisplayName("Test sayHello with different inputs")
    @ValueSource(strings = {"Alice", "Bob", "Charlie", "특수문자!@#$", "1234"})
    public void testSayHelloWithDifferentInputs(String name) {
        // When saying hello with different names
        String response = helloService.sayHello(name);

        // Then verify the response is properly formatted
        assertNotNull(response, "Response should not be null");
        assertTrue(response.contains(name), "Response should contain the provided name");
        assertEquals("Hello, Welcome to CXF Spring boot " + name + "!!!", response,
                "Response format should match expected pattern");
    }

    @Test
    @DisplayName("Test sayHello with empty string")
    public void testSayHelloWithEmptyString() {
        // Given an empty string
        String name = "";

        // When saying hello
        String response = helloService.sayHello(name);

        // Then verify the response is still constructed properly
        assertNotNull(response, "Response should not be null even with empty input");
        assertEquals("Hello, Welcome to CXF Spring boot !!!", response,
                "Response should handle empty string gracefully");
    }

    @ParameterizedTest
    @DisplayName("Test sayHello with null input")
    @NullSource
    public void testSayHelloWithNullInput(String name) {
        // When saying hello with null
        String response = helloService.sayHello(name);

        // Then verify the response handles null gracefully
        assertNotNull(response, "Response should not be null even with null input");
        assertTrue(response.contains("null"), "Response should contain 'null' string representation");
        assertEquals("Hello, Welcome to CXF Spring boot null!!!", response,
                "Response should format null as a string literal");
    }

    @Test
    @DisplayName("Test sayHello with long input")
    public void testSayHelloWithLongInput() {
        // Given a very long name
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longName.append("a");
        }

        // When saying hello
        String response = helloService.sayHello(longName.toString());

        // Then verify the service can handle long input
        assertNotNull(response, "Response should not be null with long input");
        assertTrue(response.length() > 1000, "Response should contain the long input");
        assertTrue(response.contains("Hello"), "Response should still contain greeting");
    }
}