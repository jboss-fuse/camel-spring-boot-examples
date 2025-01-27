package org.apache.camel.example.springboot;

import org.apache.camel.example.springboot.dto.ApprovalStatusDTO;
import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.example.springboot.dto.InvoiceDTO;
import org.apache.camel.example.springboot.model.Approval;
import org.apache.camel.example.springboot.model.Expense;
import org.apache.camel.example.springboot.model.Invoice;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import static org.apache.camel.example.springboot.dto.ApprovalStatusDTO.PENDING;
import static org.assertj.core.api.Assertions.assertThat;

public class ExpenseTestUtils {

    private static final Random RANDOM = new Random();

    private static final List<String> CURRENCIES = List.of("USD", "EUR", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY");


    public static ExpenseDTO createExpenses(String expenseName, String expenseDescription) {
        List<InvoiceDTO> invoices = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            InvoiceDTO invoice = InvoiceDTO.builder()
                    .date(new Date())
                    .description("Invoice " + i)
                    .amount(BigDecimal.valueOf(RANDOM.nextDouble(1000.00)))
                    .currency(CURRENCIES.get(RANDOM.nextInt(CURRENCIES.size())))
                    .build();
            invoices.add(invoice);
        }

        // Creazione dell'istanza di ExpenseDTO
        ExpenseDTO expense = ExpenseDTO.builder()
                .name(expenseName)
                .description(expenseDescription)
                .approvalStatus(PENDING)
                .invoices(invoices)
                .build();
        return expense;
    }

    public static void compareInvoices(List<InvoiceDTO> invoiceDTOs, List<Invoice> invoices) {
        if (invoiceDTOs == null && invoices == null) {
            return;
        }

        if (invoiceDTOs != null && invoices != null) {
            assertThat(invoiceDTOs.size()).isEqualTo(invoices.size());

            for (InvoiceDTO invoiceDTO : invoiceDTOs) {
                Invoice invoiceModel =  invoices.stream()
                        .filter(invoice -> invoice.getId().equals(invoiceDTO.getId()))
                        .findFirst()
                        .get();
                compareInvoices(invoiceDTO, invoiceModel);
            }
        }

    }


    public static void compareInvoices(InvoiceDTO invoiceDTO, Invoice invoice) {
        assertThat(invoiceDTO.getId()).isEqualTo(invoice.getId());
        assertThat(invoiceDTO.getDate()).isEqualTo(invoice.getDate());
        assertThat(invoiceDTO.getDescription()).isEqualTo(invoice.getDescription());
        assertThat(invoiceDTO.getAmount()).isEqualTo(invoice.getAmount());
        assertThat(invoiceDTO.getCurrency()).isEqualTo(invoice.getCurrency());
    }

    public static void compareExpenses(ExpenseDTO dto, Expense model) {
        assertThat(dto.getId()).isEqualTo(model.getId());
        assertThat(dto.getDescription()).isEqualTo(model.getDescription());
        compareInvoices(dto.getInvoices(), model.getInvoices());
        compareApproval(dto, model.getApproval());
    }

    public static void compareApproval(ExpenseDTO expenseDTO, Approval approvalStatus) {
        if(expenseDTO.getApprovalStatus().equals(ApprovalStatusDTO.PENDING)){
            assertThat(approvalStatus).isNull();
        }

        if(!expenseDTO.getApprovalStatus().equals(ApprovalStatusDTO.PENDING)){
            assertThat(approvalStatus).isNotNull();
        }

        if(expenseDTO.getApprovalStatus().equals(ApprovalStatusDTO.APPROVED)){
            assertThat(approvalStatus).isNotNull();
            assertThat(expenseDTO.getApprover()).isEqualTo(approvalStatus.getApprover());
            assertThat(expenseDTO.getApprovalDate()).isEqualTo(approvalStatus.getApprovalDate());
            assertThat(approvalStatus.getApproved()).isTrue();
        }

        if(expenseDTO.getApprovalStatus().equals(ApprovalStatusDTO.REJECTED)){
            assertThat(approvalStatus).isNotNull();
            assertThat(expenseDTO.getApprover()).isEqualTo(approvalStatus.getApprover());
            assertThat(expenseDTO.getApprovalDate()).isEqualTo(approvalStatus.getApprovalDate());
            assertThat(approvalStatus.getApproved()).isFalse();
        }



    }


}
