package org.apache.camel.example.springboot.exception;

public class ExpenseNotFoundException extends Exception {
    private Long expenseId;
    private String message;

    public ExpenseNotFoundException(Long expenseId, String message) {
        this.expenseId = expenseId;
        this.message = message;
    }

    public Long getExpenseId() {
        return expenseId;
    }

    public void setExpenseId(Long expenseId) {
        this.expenseId = expenseId;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
