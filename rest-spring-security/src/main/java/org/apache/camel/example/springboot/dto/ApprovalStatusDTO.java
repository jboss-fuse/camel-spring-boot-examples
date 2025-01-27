package org.apache.camel.example.springboot.dto;

import com.fasterxml.jackson.annotation.JsonValue;



public enum ApprovalStatusDTO {

    APPROVED("approved"),
    REJECTED("rejected"),
    PENDING("pending");

    private final String value;

    private ApprovalStatusDTO(String value) {
/*        if (!isValid(value)) {
           throw new IllegalArgumentException("Invalid approval status: " + value);
        }*/
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    public static ApprovalStatusDTO fromValue(String v) {
        for (ApprovalStatusDTO c : ApprovalStatusDTO.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    private static boolean isValid(String value){
        for (ApprovalStatusDTO c : ApprovalStatusDTO.values()) {
            if (c.value.equals(value)) {
                return true;
            }
        }
        return false;
    }
}


