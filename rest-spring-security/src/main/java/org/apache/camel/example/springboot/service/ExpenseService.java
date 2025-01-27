package org.apache.camel.example.springboot.service;

import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.example.springboot.exception.ExpenseNotFoundException;
import org.apache.camel.example.springboot.mapper.ExpenseMapper;
import org.apache.camel.example.springboot.model.Approval;
import org.apache.camel.example.springboot.model.Expense;
import org.apache.camel.example.springboot.repository.ExpenseRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service("expenseService")
public class ExpenseService {

    private ExpenseRepository expenseRepository;

    private ExpenseMapper expenseMapper = ExpenseMapper.INSTANCE;

    @Autowired
    public ExpenseService(ExpenseRepository expenseRepository) {
        this.expenseRepository = expenseRepository;
    }


    public List<ExpenseDTO> getExpenses() {
        List<Expense> expenses = this.expenseRepository.findAll();
        return expenses.stream().map(expenseMapper::toDTO).collect(Collectors.toList());
    }

    public ExpenseDTO getExpense(Long id) {
        Expense expense =  this.expenseRepository.findById(id).orElse(null);
        return expenseMapper.toDTO(expense);
    }


    public ExpenseDTO createExpense(ExpenseDTO expenseDTO) {
        Expense expense = expenseMapper.toModel(expenseDTO);
        if (expense == null) {
            throw new IllegalArgumentException("Invalid expense");
        }
        expense.setId(null);
        if(expense.getInvoices() != null && !expense.getInvoices().isEmpty()) {
            expense.getInvoices().forEach(invoice -> {invoice.setId(null); invoice.setExpense(expense);});
        }
        Expense savedExpense = this.expenseRepository.save(expense);
        return expenseMapper.toDTO(savedExpense);
    }


    public ExpenseDTO approveExpense(Long id) throws ExpenseNotFoundException {
        return approveExpense(id, true);
    }

    public ExpenseDTO rejectExpense(Long id) throws ExpenseNotFoundException {
        return approveExpense(id, false);
    }


    public ExpenseDTO approveExpense(Long id, boolean approved) throws ExpenseNotFoundException {
        Expense expense = expenseRepository.findById(id).orElseThrow(() -> new ExpenseNotFoundException(id, "Expense not found"));
       String approver = SecurityContextHolder.getContext().getAuthentication().getName();
        Approval approval = new Approval();
        approval.setApproved(approved);
        approval.setExpense(expense);
        approval.setId(null);
        approval.setApprover(approver);
        expense.setApproval(approval);
        Expense savedExpense = expenseRepository.save(expense);
        return expenseMapper.toDTO(savedExpense);
    }

}
