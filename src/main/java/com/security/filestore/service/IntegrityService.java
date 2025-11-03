package com.security.filestore.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 完整性验证服务 - 提供SHA-1哈希计算和验证
 */
@Slf4j
@Service
public class IntegrityService {

    private static final String HASH_ALGORITHM = "SHA-1";
    private static final String ENHANCED_HASH_ALGORITHM = "SHA-256";

    /**
     * 计算文件的SHA-1哈希值
     * @param file 文件
     * @return 十六进制哈希字符串
     */
    public String calculateFileHash(File file) throws IOException, NoSuchAlgorithmException {
        return calculateFileHash(file, HASH_ALGORITHM);
    }

    /**
     * 计算文件的哈希值（支持多种算法）
     * @param file 文件
     * @param algorithm 哈希算法（SHA-1, SHA-256等）
     * @return 十六进制哈希字符串
     */
    public String calculateFileHash(File file, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        log.info("计算文件哈希: {} (算法: {})", file.getName(), algorithm);

        MessageDigest digest = MessageDigest.getInstance(algorithm);

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hashBytes = digest.digest();
        String hash = HexFormat.of().formatHex(hashBytes);

        log.info("文件哈希计算完成: {}", hash);
        return hash;
    }

    /**
     * 验证文件完整性
     * @param file 文件
     * @param expectedHash 期望的哈希值
     * @return 是否完整
     */
    public boolean verifyFileIntegrity(File file, String expectedHash)
            throws IOException, NoSuchAlgorithmException {
        log.info("验证文件完整性: {}", file.getName());

        String actualHash = calculateFileHash(file);
        boolean isValid = actualHash.equalsIgnoreCase(expectedHash);

        if (isValid) {
            log.info("文件完整性验证通过");
        } else {
            log.warn("文件完整性验证失败 - 期望: {}, 实际: {}",
                    expectedHash, actualHash);
        }

        return isValid;
    }

    /**
     * 计算增强型哈希（SHA-256）
     */
    public String calculateEnhancedHash(File file)
            throws IOException, NoSuchAlgorithmException {
        return calculateFileHash(file, ENHANCED_HASH_ALGORITHM);
    }

    /**
     * 计算字节数组的哈希
     */
    public String calculateHash(byte[] data, String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(data);
        return HexFormat.of().formatHex(hashBytes);
    }

    /**
     * 计算字符串的哈希
     */
    public String calculateStringHash(String data, String algorithm)
            throws NoSuchAlgorithmException {
        return calculateHash(data.getBytes(), algorithm);
    }
}