package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class DataInitializer implements CommandLineRunner {

    private final IUserRepository userRepository;
    private final EncryptionService encryptionService;
    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    public DataInitializer(IUserRepository userRepository, EncryptionService encryptionService) {
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
    }

    @Override
    public void run(String... args) throws Exception {
        initializeUserKey("admin@pki-system.com");
        initializeUserKey("causer@pki-system.com");
    }

    private void initializeUserKey(String userEmail) {
        userRepository.findByEmail(userEmail).ifPresent(user -> {
            if (user.getSymmetricKey() == null || user.getSymmetricKey().isEmpty()) {
                logger.info("Korisnik {} nema simetrični ključ. Generišem novi...", userEmail);
                try {
                    String plainUserKey = encryptionService.generateSymmetricKey();
                    String encryptedUserKey = encryptionService.encryptUserKey(plainUserKey);
                    user.setSymmetricKey(encryptedUserKey);
                    userRepository.save(user);
                    logger.info("Simetrični ključ za korisnika {} uspešno generisan i sačuvan.", userEmail);
                } catch (Exception e) {
                    logger.error("FATALNA GREŠKA: Nije moguće generisati simetrični ključ za korisnika {}.", userEmail, e);
                }
            } else {
                logger.info("Korisnik {} već ima simetrični ključ.", userEmail);
            }
        });
    }
}