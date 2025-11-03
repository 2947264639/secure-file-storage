package com.security.filestore;

import com.security.filestore.service.IntegrityService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class IntegrityServiceTest {

    private IntegrityService integrityService;
    private File tempFile;

    @BeforeEach
    void setUp() throws Exception {
        integrityService = new IntegrityService();
        tempFile = File.createTempFile("integrity-test", ".txt");
        try (FileWriter w = new FileWriter(tempFile)) {
            w.write("Hello Security Storage!\nThis is a test file.");
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(tempFile.toPath());
    }

    @Test
    void sha1AndSha256HashShouldWork() throws Exception {
        String sha1 = integrityService.calculateFileHash(tempFile);
        String sha256 = integrityService.calculateEnhancedHash(tempFile);

        assertNotNull(sha1);
        assertNotNull(sha256);
        assertNotEquals(sha1, sha256);

        assertTrue(sha1.matches("[0-9a-fA-F]{40}"));
        assertTrue(sha256.matches("[0-9a-fA-F]{64}"));
    }

    @Test
    void verifyFileIntegrityShouldPass() throws Exception {
        String expected = integrityService.calculateFileHash(tempFile);
        assertTrue(integrityService.verifyFileIntegrity(tempFile, expected));
    }
}


