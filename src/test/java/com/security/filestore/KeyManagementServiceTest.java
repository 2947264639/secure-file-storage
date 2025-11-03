package com.security.filestore;

import com.security.filestore.service.KeyManagementService;
import com.security.filestore.service.SignatureService;
import org.junit.jupiter.api.*;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class KeyManagementServiceTest {

    private KeyManagementService kms;
    private SignatureService signatureService;
    private File tempDir;
    private File keystoreFile;
    private File backupFile;
    private String password = "keystore123";

    @BeforeEach
    void setUp() throws Exception {
        kms = new KeyManagementService();
        signatureService = new SignatureService();
        tempDir = Files.createTempDirectory("kms-test").toFile();
        keystoreFile = new File(tempDir, "user.p12");
        backupFile = new File(tempDir, "backup.p12");
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(keystoreFile.toPath());
        Files.deleteIfExists(backupFile.toPath());
        Files.deleteIfExists(tempDir.toPath());
    }

    @Test
    void createStoreExportImportAndBackupFlow() throws Exception {
        KeyStore ks = kms.createKeyStore(keystoreFile, password);
        assertTrue(keystoreFile.exists());

        KeyPair kp = signatureService.generateKeyPair();
        kms.storeKeyPairWithCertificate(ks, "user-key", kp, password, "CN=Test, O=Org, C=CN");
        kms.saveKeyStore(ks, keystoreFile, password);

        KeyStore loaded = kms.loadKeyStore(keystoreFile, password);
        PrivateKey privateKey = kms.getPrivateKey(loaded, "user-key", password);
        PublicKey publicKey = kms.getPublicKey(loaded, "user-key");
        assertNotNull(privateKey);
        assertNotNull(publicKey);

        // 证书信息与验证
        X509Certificate cert = kms.getCertificate(loaded, "user-key");
        assertTrue(kms.verifyCertificate(cert));
        assertNotNull(kms.getCertificateInfo(cert));

        // 导出、导入公钥
        File pubFile = new File(tempDir, "pub.pem");
        kms.exportPublicKey(publicKey, pubFile);
        assertTrue(pubFile.exists());
        PublicKey importedPub = kms.importPublicKey(pubFile);
        assertEquals(publicKey, importedPub);

        // 导出、导入私钥
        File encPriv = new File(tempDir, "priv.enc");
        kms.exportPrivateKey(privateKey, encPriv, "pwd!123");
        assertTrue(encPriv.exists());
        PrivateKey importedPriv = kms.importPrivateKey(encPriv, "pwd!123");
        assertEquals(privateKey.getAlgorithm(), importedPriv.getAlgorithm());

        // 备份
        kms.backupKeyStore(keystoreFile, backupFile);
        assertTrue(backupFile.exists());
        assertTrue(backupFile.length() > 0);
    }
}


