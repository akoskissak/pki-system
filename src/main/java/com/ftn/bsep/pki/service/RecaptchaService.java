package com.ftn.bsep.pki.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class RecaptchaService {
    @Value("${recaptcha.secret}")
    private String secret;

    private static final Logger logger = LoggerFactory.getLogger(RecaptchaService.class);


    private final RestTemplate restTemplate = new RestTemplate();
    
    public boolean verify(String token){
        try {
            String url = "https://www.google.com/recaptcha/api/siteverify?secret=" + secret + "&response=" + token;
            Map response = restTemplate.postForObject(url, null, Map.class);
            
            boolean success = (Boolean) response.get("success");
    
            if(!success) {
                logger.warn("Neuspešan login – CAPTCHA fail");
            }
    
            return success;
        } catch (Exception e) {
            logger.error("Error during CAPTCHA verification", e);
            return false;
        }
    }
}
