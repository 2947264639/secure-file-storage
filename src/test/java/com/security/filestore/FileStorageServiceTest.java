package com.security.filestore;

import com.security.filestore.model.FileMetadata;
import com.security.filestore.service.*;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class FileStorageServiceTest {

    private FileStorageService storageService;
    private EncryptionService encryptionService;
    private SignatureService signatureService;
    private IntegrityService integrityService;
    private KeyManagementService keyManagementService;
    private Path baseDir;

    @BeforeEach
    void setUp() throws Exception {
        baseDir = Files.createTempDirectory("storage-test");
        encryptionService = new EncryptionService();
        signatureService = new SignatureService();
        integrityService = new IntegrityService();
        keyManagementService = new KeyManagementService();

        // inject IntegrityService into SignatureService
        Field fld = SignatureService.class.getDeclaredField("integrityService");
        fld.setAccessible(true);
        fld.set(signatureService, integrityService);

        storageService = new FileStorageService();
        // reflect inject dependencies and values
        setPrivate(storageService, "encryptionService", encryptionService);
        setPrivate(storageService, "signatureService", signatureService);
        setPrivate(storageService, "integrityService", integrityService);
        setPrivate(storageService, "baseDir", baseDir.toString());
        setPrivate(storageService, "encryptedDir", "encrypted");
        setPrivate(storageService, "decryptedDir", "decrypted");
        setPrivate(storageService, "signatureDir", "signatures");

        storageService.init();
    }

    @AfterEach
    void tearDown() throws Exception {
        // cleanup temp directory
        Files.walk(baseDir)
                .sorted((a,b) -> b.getNameCount()-a.getNameCount())
                .forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception ignored) {} });
    }

    @Test
    void uploadEncryptDecryptAndVerifySignature() throws Exception {
        // prepare input file
        File input = new File(baseDir.toFile(), "input.txt");
        try (FileWriter w = new FileWriter(input)) {
            w.write("storage-service end2end test content\n你好");
        }

        KeyPair kp = signatureService.generateKeyPair();

        // upload & encrypt & sign
        FileMetadata md = storageService.uploadAndEncryptFile(input, "Pwd-123456", true, kp.getPrivate());
        assertNotNull(md.getFileId());
        assertTrue(new File(md.getEncryptedFilePath()).exists());
        assertTrue(md.isEncrypted());
        assertTrue(md.isSigned());

        // decrypt
        File dec = storageService.decryptFile(md.getFileId(), "Pwd-123456");
        assertTrue(dec.exists());

        // verify signature (uses decrypted file)
        boolean ok = storageService.verifyFileSignature(md.getFileId(), kp.getPublic());
        assertTrue(ok);
    }

    private static void setPrivate(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }
}


