package org.apache.camel.example.springboot.model;

import jakarta.persistence.*;

import java.util.Date;

@Entity
public class Approval {

    public Approval() {
    }

    @Id
    @GeneratedValue(strategy= GenerationType.SEQUENCE, generator = "APPROVAL_SEQ")
    @SequenceGenerator(name = "APPROVAL_SEQ", sequenceName = "APPROVAL_SEQ", allocationSize = 1)

    private Long id;

    private String approver;

    private Boolean approved;

    private Date approvalDate;

    public Approval(Long id, String approver, Boolean approved, Date approvalDate, Expense expense) {
        this.id = id;
        this.approver = approver;
        this.approved = approved;
        this.approvalDate = approvalDate;
        this.expense = expense;
    }

    public Approval( String approver, Boolean approved, Date approvalDate) {
        this.id = null;
        this.approver = approver;
        this.approved = approved;
        this.approvalDate = approvalDate;
        this.expense = null;
    }

    @OneToOne
    @JoinColumn(name = "expense_id", insertable = false, updatable = false)
    private Expense expense;

    public Expense getExpense() {
        return expense;
    }

    public void setExpense(Expense expense) {
        this.expense = expense;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getApprover() {
        return approver;
    }

    public void setApprover(String approver) {
        this.approver = approver;
    }

    public Boolean getApproved() {
        return approved;
    }

    public void setApproved(Boolean approved) {
        this.approved = approved;
    }

    public Date getApprovalDate() {
        return approvalDate;
    }

    public void setApprovalDate(Date approvalDate) {
        this.approvalDate = approvalDate;
    }
}
