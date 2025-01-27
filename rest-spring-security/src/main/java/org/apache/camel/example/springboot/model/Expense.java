package org.apache.camel.example.springboot.model;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "EXPENSE")
public class Expense {

    @Id
    @GeneratedValue(strategy= GenerationType.SEQUENCE, generator = "EXPENSE_SEQ")
    @SequenceGenerator(name = "EXPENSE_SEQ", sequenceName = "EXPENSE_SEQ", allocationSize = 1)
    private Long id;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "expense", cascade = CascadeType.ALL)
    private List<Invoice> invoices;

    private String name;

    private String description;

    @OneToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinColumn(name="APPROVAL_ID", unique=true)
    private Approval approval;



    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public List<Invoice> getInvoices() {
        return invoices;
    }

    public void setInvoices(List<Invoice> invoices) {
        this.invoices = invoices;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Approval getApproval() {
        return approval;
    }

    public void setApproval(Approval approval) {
        this.approval = approval;
    }
}
