package com.security.filestore.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 数字签名服务 - 提供RSA签名和验证功能
 */
@Slf4j
@Service
public class SignatureService {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int RSA_KEY_SIZE = 2048;

    @Autowired
    private IntegrityService integrityService;

    /**
     * 生成RSA密钥对
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        log.info("生成RSA密钥对...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        log.info("RSA密钥对生成成功");
        return keyPair;
    }

    /**
     * 对文件进行数字签名
     * @param file 要签名的文件
     * @param privateKey 私钥
     * @return 签名字节数组
     */
    public byte[] signFile(File file, PrivateKey privateKey)
            throws Exception {
        log.info("对文件进行数字签名: {}", file.getName());

        // 首先计算文件哈希
        String fileHash = integrityService.calculateFileHash(file, "SHA-256");

        // 使用私钥对哈希进行签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(HexFormat.of().parseHex(fileHash));

        byte[] signatureBytes = signature.sign();
        log.info("文件签名完成，签名长度: {} bytes", signatureBytes.length);

        return signatureBytes;
    }

    /**
     * 验证文件签名
     * @param file 文件
     * @param signatureBytes 签名
     * @param publicKey 公钥
     * @return 签名是否有效
     */
    public boolean verifyFileSignature(File file, byte[] signatureBytes,
                                       PublicKey publicKey) throws Exception {
        log.info("验证文件签名: {}", file.getName());

        // 计算文件哈希
        String fileHash = integrityService.calculateFileHash(file, "SHA-256");

        // 使用公钥验证签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(HexFormat.of().parseHex(fileHash));

        boolean isValid = signature.verify(signatureBytes);

        if (isValid) {
            log.info("签名验证成功");
        } else {
            log.warn("签名验证失败");
        }

        return isValid;
    }

    /**
     * 保存签名到文件
     * @param signatureBytes 签名数据
     * @param signatureFile 签名文件
     */
    public void saveSignatureToFile(byte[] signatureBytes, File signatureFile)
            throws IOException {
        try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
            // 保存为Base64编码便于查看
            String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);
            fos.write(base64Signature.getBytes());
        }
        log.info("签名已保存到文件: {}", signatureFile.getName());
    }

    /**
     * 从文件加载签名
     * @param signatureFile 签名文件
     * @return 签名字节数组
     */
    public byte[] loadSignatureFromFile(File signatureFile) throws IOException {
        String base64Signature = Files.readString(signatureFile.toPath());
        byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
        log.info("从文件加载签名: {}", signatureFile.getName());
        return signatureBytes;
    }

    /**
     * 对文件签名并保存
     * @param file 要签名的文件
     * @param privateKey 私钥
     * @param signatureFile 签名保存位置
     */
    public void signAndSaveFile(File file, PrivateKey privateKey, File signatureFile)
            throws Exception {
        byte[] signature = signFile(file, privateKey);
        saveSignatureToFile(signature, signatureFile);
    }

    /**
     * 加载签名并验证文件
     * @param file 文件
     * @param signatureFile 签名文件
     * @param publicKey 公钥
     * @return 验证结果
     */
    public boolean loadAndVerifyFile(File file, File signatureFile, PublicKey publicKey)
            throws Exception {
        byte[] signature = loadSignatureFromFile(signatureFile);
        return verifyFileSignature(file, signature, publicKey);
    }
}