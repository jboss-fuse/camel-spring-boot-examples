package org.apache.camel.example.springboot.dto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

import java.math.BigDecimal;
import java.util.Date;


@Value
@Builder
@Jacksonized
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class InvoiceDTO {
    
     Long id;

     Date date;

     String description;

     BigDecimal amount;

     String currency;

}
