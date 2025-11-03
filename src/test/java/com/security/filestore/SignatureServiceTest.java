package com.security.filestore;

import com.security.filestore.service.IntegrityService;
import com.security.filestore.service.SignatureService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class SignatureServiceTest {

    private SignatureService signatureService;
    private IntegrityService integrityService;
    private File input;

    @BeforeEach
    void setUp() throws Exception {
        signatureService = new SignatureService();
        integrityService = new IntegrityService();
        // inject IntegrityService via reflection (field is package-private @Autowired in prod)
        var fld = SignatureService.class.getDeclaredField("integrityService");
        fld.setAccessible(true);
        fld.set(signatureService, integrityService);

        input = File.createTempFile("sign-input", ".txt");
        try (FileWriter w = new FileWriter(input)) {
            w.write("signature-test\n内容-ABC-123");
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(input.toPath());
    }

    @Test
    void signAndVerifyShouldPass() throws Exception {
        KeyPair kp = signatureService.generateKeyPair();
        byte[] sig = signatureService.signFile(input, kp.getPrivate());
        assertNotNull(sig);
        assertTrue(sig.length > 0);

        boolean ok = signatureService.verifyFileSignature(input, sig, kp.getPublic());
        assertTrue(ok);
    }
}


