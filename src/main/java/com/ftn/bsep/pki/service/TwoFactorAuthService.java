package com.ftn.bsep.pki.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Service
public class TwoFactorAuthService {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String generateSecret() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public String generateQRUrl(String appName, String email, String secret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                appName, email, secret, appName);
    }

    public String generateQRImage(String qrCodeData) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        var bitMatrix = qrCodeWriter.encode(qrCodeData, BarcodeFormat.QR_CODE, 200, 200);
        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        return Base64.getEncoder().encodeToString(pngOutputStream.toByteArray());
    }

    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}
