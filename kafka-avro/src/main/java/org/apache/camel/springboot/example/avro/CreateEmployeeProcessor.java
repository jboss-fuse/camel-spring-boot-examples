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
package org.apache.camel.springboot.example.avro;

import com.github.javafaker.Faker;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class CreateEmployeeProcessor implements Processor {
    private final Faker faker = new Faker();

    @Override
    public void process(Exchange exchange) throws Exception {
        final String firstName = faker.name().firstName();
        final String lastName = faker.name().lastName();
        final Date hireDate = faker.date().past(365, TimeUnit.DAYS);

        Map<String, String> personal = new HashMap<>();
        personal.put("address", faker.address().streetAddress());
        personal.put("phone", faker.phoneNumber().cellPhone());

        exchange.getIn().setBody(new Employee(firstName, lastName, hireDate.getTime(), personal));
    }
}
