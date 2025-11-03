package com.security.filestore.service;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * 加密服务 - 提供AES加密/解密和密钥派生功能
 */
@Slf4j
@Service
public class EncryptionService {

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256; // AES-256
    private static final int IV_SIZE = 16;   // 128 bits
    private static final int SALT_SIZE = 32; // 256 bits
    private static final int ITERATION_COUNT = 65536;

    static {
        // 注册Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 从密码派生密钥
     * @param password 用户密码
     * @param salt 盐值
     * @return 派生的密钥
     */
    public SecretKey deriveKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 生成随机盐值
     */
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * 生成随机IV
     */
    public byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * 加密文件
     * @param inputFile 输入文件
     * @param outputFile 输出文件
     * @param password 加密密码
     * @return 加密元数据（盐值、IV）
     */
    public EncryptionMetadata encryptFile(File inputFile, File outputFile, String password)
            throws Exception {
        log.info("开始加密文件: {}", inputFile.getName());

        // 生成盐值和IV
        byte[] salt = generateSalt();
        byte[] iv = generateIV();

        // 派生密钥
        SecretKey key = deriveKeyFromPassword(password, salt);

        // 初始化加密器
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // 写入文件头：盐值 + IV
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             DataOutputStream dos = new DataOutputStream(fos);
             FileInputStream fis = new FileInputStream(inputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            // 写入盐值长度和盐值
            dos.writeInt(salt.length);
            dos.write(salt);

            // 写入IV长度和IV
            dos.writeInt(iv.length);
            dos.write(iv);

            // 加密文件内容
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }

        log.info("文件加密完成: {}", outputFile.getName());
        return new EncryptionMetadata(salt, iv);
    }

    /**
     * 解密文件
     * @param inputFile 加密文件
     * @param outputFile 输出文件
     * @param password 解密密码
     */
    public void decryptFile(File inputFile, File outputFile, String password)
            throws Exception {
        log.info("开始解密文件: {}", inputFile.getName());

        try (FileInputStream fis = new FileInputStream(inputFile);
             DataInputStream dis = new DataInputStream(fis);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // 读取盐值
            int saltLength = dis.readInt();
            byte[] salt = new byte[saltLength];
            dis.readFully(salt);

            // 读取IV
            int ivLength = dis.readInt();
            byte[] iv = new byte[ivLength];
            dis.readFully(iv);

            // 派生密钥
            SecretKey key = deriveKeyFromPassword(password, salt);

            // 初始化解密器
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            // 解密文件内容
            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            log.error("解密失败: 密码错误", e);
            throw new SecurityException("密码错误或文件已损坏");
        }

        log.info("文件解密完成: {}", outputFile.getName());
    }

    /**
     * 加密元数据
     */
    public static class EncryptionMetadata {
        private final byte[] salt;
        private final byte[] iv;

        public EncryptionMetadata(byte[] salt, byte[] iv) {
            this.salt = salt;
            this.iv = iv;
        }

        public byte[] getSalt() { return salt; }
        public byte[] getIv() { return iv; }
    }
}