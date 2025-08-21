package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class ApiResponse {
    private String message;
    private String error;
    private Object data;
    

    public ApiResponse(String message, String error, Object data) {
        this.message = message;
        this.error = error;
        this.data = data;
    }

    public static ApiResponse success(String message) {
        return new ApiResponse(message, null, null);
    }
    
    public static ApiResponse successWithData(String message, Object data) {
        return new ApiResponse(message, null, data);
    }

    public static ApiResponse failure(String error) {
        return new ApiResponse(null, error, null);
    }
}