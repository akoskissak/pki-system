package com.ftn.bsep.pki.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
  private final JavaMailSender mailSender;
  private final String fromEmail;
  
  public EmailService(JavaMailSender mailSender, @Value("${spring.mail.from}") String fromEmail){
    this.mailSender = mailSender;
    this.fromEmail = fromEmail;
  }
  
  public void sendEmail(String to, String subject, String text) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setSubject(subject);
    message.setText(text);
    message.setFrom(fromEmail);
    mailSender.send(message);
  }
}
