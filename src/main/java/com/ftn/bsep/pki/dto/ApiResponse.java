package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class ApiResponse {
    private String message;
    private String error;
    

    public ApiResponse(String message, String error) {
        this.message = message;
        this.error = error;
    }

    public static ApiResponse success(String message) {
        return new ApiResponse(message, null);
    }

    public static ApiResponse failure(String error) {
        return new ApiResponse(null, error);
    }
}