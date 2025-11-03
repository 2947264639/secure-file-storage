package com.security.filestore.service;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * 密钥管理服务 - 提供密钥的存储、导出、导入、备份功能
 */
@Slf4j
@Service
public class KeyManagementService {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String CERT_SIGN_ALGORITHM = "SHA256withRSA";

    /**
     * 创建密钥库
     * @param keystoreFile 密钥库文件
     * @param keystorePassword 密钥库密码
     */
    public KeyStore createKeyStore(File keystoreFile, String keystorePassword)
            throws Exception {
        log.info("创建新密钥库: {}", keystoreFile.getName());

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, keystorePassword.toCharArray());

        // 保存密钥库
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }

        log.info("密钥库创建成功");
        return keyStore;
    }

    /**
     * 加载密钥库
     */
    public KeyStore loadKeyStore(File keystoreFile, String keystorePassword)
            throws Exception {
        log.info("加载密钥库: {}", keystoreFile.getName());

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        log.info("密钥库加载成功");
        return keyStore;
    }

    /**
     * 生成自签名证书
     */
    public X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subject)
            throws Exception {
        log.info("生成自签名证书: {}", subject);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1年有效期

        X500Name dnName = new X500Name(subject);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                startDate,
                endDate,
                dnName,
                keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_SIGN_ALGORITHM)
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(certHolder);

        log.info("自签名证书生成成功");
        return cert;
    }

    /**
     * 将密钥对和证书存储到密钥库
     */
    public void storeKeyPairWithCertificate(KeyStore keyStore, String alias,
                                            KeyPair keyPair, String keyPassword,
                                            String subject) throws Exception {
        log.info("存储密钥对和证书到密钥库，别名: {}", alias);

        // 生成自签名证书
        X509Certificate cert = generateSelfSignedCertificate(keyPair, subject);

        // 存储私钥和证书链
        Certificate[] certChain = new Certificate[]{cert};
        keyStore.setKeyEntry(alias, keyPair.getPrivate(),
                keyPassword.toCharArray(), certChain);

        log.info("密钥对和证书存储成功");
    }

    /**
     * 从密钥库获取私钥
     */
    public PrivateKey getPrivateKey(KeyStore keyStore, String alias, String keyPassword)
            throws Exception {
        log.info("从密钥库获取私钥，别名: {}", alias);
        Key key = keyStore.getKey(alias, keyPassword.toCharArray());

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new KeyStoreException("指定别名不包含私钥");
    }

    /**
     * 从密钥库获取公钥
     */
    public PublicKey getPublicKey(KeyStore keyStore, String alias) throws Exception {
        log.info("从密钥库获取公钥，别名: {}", alias);
        Certificate cert = keyStore.getCertificate(alias);

        if (cert != null) {
            return cert.getPublicKey();
        }
        throw new KeyStoreException("指定别名不包含证书");
    }

    /**
     * 导出公钥到文件（PEM格式）
     */
    public void exportPublicKey(PublicKey publicKey, File outputFile) throws IOException {
        log.info("导出公钥到文件: {}", outputFile.getName());

        String base64PublicKey = Base64.getEncoder()
                .encodeToString(publicKey.getEncoded());

        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(base64PublicKey.replaceAll("(.{64})", "$1\n"));
            writer.write("\n-----END PUBLIC KEY-----\n");
        }

        log.info("公钥导出成功");
    }

    /**
     * 导入公钥从文件
     */
    public PublicKey importPublicKey(File inputFile) throws Exception {
        log.info("从文件导入公钥: {}", inputFile.getName());

        String content = new String(java.nio.file.Files.readAllBytes(inputFile.toPath()));
        content = content.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(content);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        log.info("公钥导入成功");
        return keyFactory.generatePublic(spec);
    }

    /**
     * 导出私钥到加密文件
     */
    public void exportPrivateKey(PrivateKey privateKey, File outputFile,
                                 String password) throws Exception {
        log.info("导出加密私钥到文件: {}", outputFile.getName());

        // 使用AES加密私钥
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // 派生密钥
        SecretKey aesKey = deriveKey(password, salt);

        // 加密私钥
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] encryptedKey = cipher.doFinal(privateKey.getEncoded());

        // 保存到文件
        try (DataOutputStream dos = new DataOutputStream(
                new FileOutputStream(outputFile))) {
            dos.writeInt(salt.length);
            dos.write(salt);
            dos.writeInt(iv.length);
            dos.write(iv);
            dos.writeInt(encryptedKey.length);
            dos.write(encryptedKey);
        }

        log.info("私钥导出成功");
    }

    /**
     * 从加密文件导入私钥
     */
    public PrivateKey importPrivateKey(File inputFile, String password) throws Exception {
        log.info("从加密文件导入私钥: {}", inputFile.getName());

        try (DataInputStream dis = new DataInputStream(
                new FileInputStream(inputFile))) {

            // 读取盐值
            int saltLen = dis.readInt();
            byte[] salt = new byte[saltLen];
            dis.readFully(salt);

            // 读取IV
            int ivLen = dis.readInt();
            byte[] iv = new byte[ivLen];
            dis.readFully(iv);

            // 读取加密的私钥
            int keyLen = dis.readInt();
            byte[] encryptedKey = new byte[keyLen];
            dis.readFully(encryptedKey);

            // 派生密钥
            SecretKey aesKey = deriveKey(password, salt);

            // 解密私钥
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] keyBytes = cipher.doFinal(encryptedKey);

            // 重建私钥
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            log.info("私钥导入成功");
            return keyFactory.generatePrivate(spec);
        }
    }

    /**
     * 保存密钥库
     */
    public void saveKeyStore(KeyStore keyStore, File keystoreFile, String password)
            throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, password.toCharArray());
        }
        log.info("密钥库已保存: {}", keystoreFile.getName());
    }

    /**
     * 备份密钥库
     */
    public void backupKeyStore(File keystoreFile, File backupFile) throws IOException {
        log.info("备份密钥库: {} -> {}", keystoreFile.getName(), backupFile.getName());
        java.nio.file.Files.copy(keystoreFile.toPath(), backupFile.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        log.info("密钥库备份成功");
    }

    /**
     * 从密钥库获取证书
     */
    public X509Certificate getCertificate(KeyStore keyStore, String alias) throws Exception {
        log.info("从密钥库获取证书，别名: {}", alias);
        Certificate cert = keyStore.getCertificate(alias);
        
        if (cert instanceof X509Certificate) {
            return (X509Certificate) cert;
        }
        throw new KeyStoreException("指定别名不包含X509证书");
    }

    /**
     * 验证证书有效性
     */
    public boolean verifyCertificate(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            // 验证证书签名（自签名证书）
            certificate.verify(certificate.getPublicKey());
            log.info("证书验证成功");
            return true;
        } catch (Exception e) {
            log.warn("证书验证失败: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 获取证书详细信息字符串
     */
    public String getCertificateInfo(X509Certificate certificate) {
        StringBuilder info = new StringBuilder();
        info.append("证书主题: ").append(certificate.getSubjectDN().getName()).append("\n");
        info.append("证书颁发者: ").append(certificate.getIssuerDN().getName()).append("\n");
        info.append("序列号: ").append(certificate.getSerialNumber().toString()).append("\n");
        info.append("算法: ").append(certificate.getSigAlgName()).append("\n");
        info.append("有效期开始: ").append(certificate.getNotBefore()).append("\n");
        info.append("有效期结束: ").append(certificate.getNotAfter()).append("\n");
        info.append("证书版本: ").append(certificate.getVersion()).append("\n");
        info.append("是否有效: ").append(verifyCertificate(certificate) ? "是" : "否");
        return info.toString();
    }

    /**
     * 辅助方法：从密码派生AES密钥
     */
    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        javax.crypto.SecretKeyFactory factory =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec spec =
                new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}