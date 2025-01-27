package org.apache.camel.example.springboot;

import org.apache.camel.example.springboot.dto.ApprovalStatusDTO;
import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.example.springboot.dto.InvoiceDTO;
import org.apache.camel.example.springboot.mapper.ExpenseMapper;
import org.apache.camel.example.springboot.model.Approval;
import org.apache.camel.example.springboot.model.Expense;
import org.apache.camel.example.springboot.model.Invoice;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class ExpenseMapperTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExpenseMapperTest.class);

    @Test
    public void testExpenseMapper() {
        ExpenseMapper mapper = ExpenseMapper.INSTANCE;

        Expense expense = new Expense();
        // invoice 1
        Invoice invoice1 = new Invoice();
        invoice1.setId(1L);
        invoice1.setAmount(new BigDecimal("100.00"));
        invoice1.setCurrency("USD");
        invoice1.setDescription("Test Invoice 1");
        invoice1.setExpense(expense);
        //Saturday, January 4, 2025 8:15:14 PM GMT+01:00
        invoice1.setDate(new Date(1736021714000L));

        // invoice 2
        Invoice invoice2 = new Invoice();
        invoice2.setId(3L);
        invoice2.setAmount(new BigDecimal("32.40"));
        invoice2.setCurrency("EUR");
        invoice2.setDescription("Test Invoice 3");
        invoice2.setExpense(expense);
        //Tuesday, January 7, 2025 10:45:34 AM GMT+01:00
        invoice2.setDate(new Date(1736243134000L));

        expense.setId(1L);
        expense.setDescription("description");
        expense.setName("Expense Name");
        expense.setInvoices(Arrays.asList(invoice1, invoice2));
        expense.setApproval(new Approval(1L,"Adrián Bernabé",true, new Date(1736502334000L), expense));

        ExpenseDTO dto = mapper.toDTO(expense);

        assertThat(dto.getId()).isEqualTo(1L);
        assertThat(dto.getDescription()).isEqualTo("description");
        assertThat(dto.getName()).isEqualTo("Expense Name");
        assertThat(dto.getInvoices()).hasSize(2);
        assertThat(dto.getApprovalDate()).isBeforeOrEqualTo(expense.getApproval().getApprovalDate());
        assertThat(dto.getApprover()).isEqualTo(expense.getApproval().getApprover());
        assertThat(dto.getApprovalStatus()).isEqualTo(ApprovalStatusDTO.APPROVED);


        InvoiceDTO invoice1DTO = dto.getInvoices().get(0);
        assertThat(invoice1DTO.getId()).isEqualTo(invoice1.getId());
        assertThat(invoice1DTO.getDescription()).isEqualTo(invoice1.getDescription());
        assertThat(invoice1DTO.getAmount()).isEqualTo(invoice1.getAmount());
        assertThat(invoice1DTO.getCurrency()).isEqualTo(invoice1.getCurrency());
        assertThat(invoice1DTO.getDate()).isEqualTo(invoice1.getDate());


        InvoiceDTO invoice3DTO = dto.getInvoices().get(1);
        assertThat(invoice3DTO.getId()).isEqualTo(invoice2.getId());
        assertThat(invoice3DTO.getDescription()).isEqualTo(invoice2.getDescription());
        assertThat(invoice3DTO.getAmount()).isEqualTo(invoice2.getAmount());
        assertThat(invoice3DTO.getCurrency()).isEqualTo(invoice2.getCurrency());
        assertThat(invoice3DTO.getDate()).isEqualTo(invoice2.getDate());
    }

}
