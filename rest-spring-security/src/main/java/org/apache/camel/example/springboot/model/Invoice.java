package org.apache.camel.example.springboot.model;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Date;
import java.util.Objects;

@Entity
@Table(name = "INVOICE")
public class Invoice {
    @Id
    @GeneratedValue(strategy= GenerationType.SEQUENCE, generator = "INVOICE_SEQ")
    @SequenceGenerator(name = "INVOICE_SEQ", sequenceName = "INVOICE_SEQ", allocationSize = 1)

    private Long id;

    private Date date;

    private String description;

    private BigDecimal amount;

    private String currency;

    @ManyToOne
    @JoinColumn(name="EXPENSE_ID")
    private Expense expense;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = new BigDecimal(amount.toString()).setScale(2, RoundingMode.DOWN);
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public Expense getExpense() {
        return expense;
    }

    public void setExpense(Expense expense) {
        this.expense = expense;
    }

    @Override
    public final boolean equals(Object o) {
        if (!(o instanceof Invoice invoice)) return false;

        return Objects.equals(id, invoice.id) && Objects.equals(date, invoice.date) && Objects.equals(description, invoice.description) && Objects.equals(amount, invoice.amount) && Objects.equals(currency, invoice.currency) && Objects.equals(expense, invoice.expense);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(id);
        result = 31 * result + Objects.hashCode(date);
        result = 31 * result + Objects.hashCode(description);
        result = 31 * result + Objects.hashCode(amount);
        result = 31 * result + Objects.hashCode(currency);
        result = 31 * result + Objects.hashCode(expense);
        return result;
    }
}
