package com.ftn.bsep.pki.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class RecaptchaService {
    @Value("${recaptcha.secret}")
    private String secret;
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    public boolean verify(String token){    
        String url = "https://www.google.com/recaptcha/api/siteverify?secret=" + secret + "&response=" + token;
        Map response = restTemplate.postForObject(url, null, Map.class);
        return (Boolean) response.get("success");
    }
}
