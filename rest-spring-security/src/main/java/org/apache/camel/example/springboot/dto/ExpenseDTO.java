package org.apache.camel.example.springboot.dto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

import java.util.Date;
import java.util.List;


@Value
@Builder
@Jacksonized
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ExpenseDTO {

    Long id;

    List<InvoiceDTO> invoices;

    String name;

    String description;

    ApprovalStatusDTO approvalStatus;

    String approver;

    Date approvalDate;

}
