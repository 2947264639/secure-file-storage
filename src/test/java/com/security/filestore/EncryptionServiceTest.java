package com.security.filestore;

import com.security.filestore.service.EncryptionService;
import com.security.filestore.service.IntegrityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private IntegrityService integrityService;
    private File input;
    private File encrypted;
    private File decrypted;

    @BeforeEach
    void setUp() throws Exception {
        encryptionService = new EncryptionService();
        integrityService = new IntegrityService();

        input = File.createTempFile("enc-input", ".txt");
        try (FileWriter w = new FileWriter(input)) {
            w.write("encryption-test-file-内容123\nline2");
        }
        encrypted = new File(input.getParentFile(), input.getName() + ".enc");
        decrypted = new File(input.getParentFile(), input.getName() + ".dec");
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(input.toPath());
        Files.deleteIfExists(encrypted.toPath());
        Files.deleteIfExists(decrypted.toPath());
    }

    @Test
    void encryptThenDecryptShouldRecoverOriginal() throws Exception {
        String pwd = "StrongPassword!123";
        encryptionService.encryptFile(input, encrypted, pwd);
        assertTrue(encrypted.exists());

        encryptionService.decryptFile(encrypted, decrypted, pwd);
        assertTrue(decrypted.exists());

        String h1 = integrityService.calculateFileHash(input);
        String h2 = integrityService.calculateFileHash(decrypted);
        assertEquals(h1, h2, "Decrypted file hash should equal original");
    }
}


