package org.apache.camel.example.springboot.mapper;

import org.apache.camel.example.springboot.dto.ApprovalStatusDTO;
import org.apache.camel.example.springboot.dto.ExpenseDTO;
import org.apache.camel.example.springboot.dto.InvoiceDTO;
import org.apache.camel.example.springboot.model.Approval;
import org.apache.camel.example.springboot.model.Expense;
import org.apache.camel.example.springboot.model.Invoice;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import static org.apache.camel.example.springboot.dto.ApprovalStatusDTO.*;
import static org.mapstruct.NullValueCheckStrategy.ALWAYS;

@Mapper
public interface ExpenseMapper {

    ExpenseMapper INSTANCE = Mappers.getMapper(ExpenseMapper.class);

    @Mapping(target = "approver", source = "approval.approver", nullValueCheckStrategy = ALWAYS)
    @Mapping(target = "approvalDate", source = "approval.approvalDate", dateFormat = "yyyy.MM.dd HH:mm:ss z", nullValueCheckStrategy = ALWAYS)
    @Mapping(target = "approvalStatus", source = "approval.approved", qualifiedBy = {BooleanToApprovalStatusDTO.class},
            defaultExpression = "java(org.apache.camel.example.springboot.dto.ApprovalStatusDTO.PENDING)")
    ExpenseDTO toDTO(Expense expense);


    @InheritInverseConfiguration
//    @Mapping(target = "approval.approved", source = "approvalStatus", qualifiedBy = ApprovalStatusDTOToBoolean.class,  nullValuePropertyMappingStrategy = SET_TO_NULL )
    @Mapping(target = "approval", expression = "java(toApproval(expenseDTO))" )
    Expense toModel(ExpenseDTO expenseDTO);


    default Approval toApproval(ExpenseDTO expenseDTO){
        ApprovalStatusDTO approvalStatusDTO = expenseDTO.getApprovalStatus();
        switch (approvalStatusDTO) {
            case APPROVED:
                return  new Approval(expenseDTO.getApprover(), true, expenseDTO.getApprovalDate());
            case REJECTED:
                return  new Approval(expenseDTO.getApprover(), false, expenseDTO.getApprovalDate());
            case PENDING:
                return null;
            default:
                throw new IllegalArgumentException("Approval status not supported: " + approvalStatusDTO);
        }

    }


    @Mapping(target = "date", source = "date", dateFormat = "yyyy.MM.dd HH:mm:ss z", nullValueCheckStrategy = ALWAYS)
    @Mapping(target = "amount", source = "amount", numberFormat = "#.00")
    InvoiceDTO toDTO(Invoice invoice);


    @InheritInverseConfiguration
    @Mapping(target="id", source="invoiceDTO.id")
    @Mapping(target = "description", source="invoiceDTO.description")
    @Mapping(target="expense", source="expenseSource")
    Invoice toModel(InvoiceDTO invoiceDTO, Expense expenseSource);


    @ApprovalStatusDTOToBoolean
    default Boolean toApproved(ApprovalStatusDTO approvalStatusDTO) {
        switch (approvalStatusDTO) {
            case APPROVED:
                return true;
            case REJECTED:
                return false;
            case PENDING:
                return null;
            default:
                throw new IllegalArgumentException("Approval status not supported: " + approvalStatusDTO);
        }
    }

    @BooleanToApprovalStatusDTO
    default ApprovalStatusDTO toApprovalStatusDTO(Boolean approved) {
        if (approved == null) {
            return PENDING;
        }
        return approved ? APPROVED : REJECTED;
    }
}
