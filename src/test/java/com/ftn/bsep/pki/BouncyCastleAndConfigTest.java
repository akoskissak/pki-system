package com.ftn.bsep.pki;

import com.ftn.bsep.pki.config.KeyStoreConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class BouncyCastleAndConfigTest {
    @Autowired
    KeyStoreConfig keyStoreConfig;

    @BeforeEach
    void ensureDirs() throws Exception {
        Files.createDirectories(Path.of(keyStoreConfig.getCaDir()));
        Files.createDirectories(Path.of(keyStoreConfig.getEeDir()));
    }

    @Test
    void bouncyCastleProviderIsRegistered() {
        Provider p = Security.getProvider("BC");
        assertNotNull(p, "BouncyCastle provider should be registered (Security.getProvider(\"BC\") != null)");
    }
    @Test
    void keyStoreConfigValuesLoadedAndDirsExist() {
        assertNotNull(keyStoreConfig);
        assertTrue(keyStoreConfig.getCaDir().length() > 0);
        assertTrue(keyStoreConfig.getEeDir().length() > 0);

        File caDir = Path.of(keyStoreConfig.getCaDir()).toFile();
        File eeDir = Path.of(keyStoreConfig.getEeDir()).toFile();
        assertTrue(caDir.exists() && caDir.isDirectory(), "CA dir should exist");
        assertTrue(eeDir.exists() && eeDir.isDirectory(), "EE dir should exist");
    }
}
