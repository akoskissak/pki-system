package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import org.springframework.stereotype.Service;

@Service
public class PasswordStrengthService {
    private final Zxcvbn zxcvbn = new Zxcvbn();
    
    public Strength evaluate(String password) {
        return zxcvbn.measure(password);
    }
    
    public ApiResponse validatePassword(String password) {
        Strength strength = evaluate(password);
        if (strength.getScore() < 3) {
            String feedback = strength.getFeedback().getWarning() + " " +
                    String.join(" ", strength.getFeedback().getSuggestions());
            return ApiResponse.failure("Password is not strength enough: " + feedback);
        }
        return ApiResponse.success("Password is strength enough");
    }
}
