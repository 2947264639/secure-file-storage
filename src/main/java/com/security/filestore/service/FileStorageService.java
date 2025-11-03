package com.security.filestore.service;

import com.security.filestore.model.FileMetadata;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

//import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.*;

/**
 * 文件存储服务 - 管理文件的存储、加密、签名等操作
 */
@Slf4j
@Service
public class FileStorageService {

    @Value("${storage.base-dir:./secure-storage}")
    private String baseDir;

    @Value("${storage.encrypted-dir:encrypted}")
    private String encryptedDir;

    @Value("${storage.decrypted-dir:decrypted}")
    private String decryptedDir;

    @Value("${storage.signature-dir:signatures}")
    private String signatureDir;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private IntegrityService integrityService;

    // 内存中的文件元数据存储
    private Map<String, FileMetadata> fileMetadataMap = new HashMap<>();

    @PostConstruct
    public void init() throws IOException {
        // 初始化存储目录
        createDirectoryIfNotExists(baseDir);
        createDirectoryIfNotExists(Paths.get(baseDir, encryptedDir).toString());
        createDirectoryIfNotExists(Paths.get(baseDir, decryptedDir).toString());
        createDirectoryIfNotExists(Paths.get(baseDir, signatureDir).toString());

        log.info("文件存储服务初始化完成，基础目录: {}", baseDir);
    }

    private void createDirectoryIfNotExists(String dir) throws IOException {
        Path path = Paths.get(dir);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
            log.info("创建目录: {}", dir);
        }
    }

    /**
     * 上传并加密文件
     * @param sourceFile 源文件
     * @param password 加密密码
     * @param shouldSign 是否签名
     * @param privateKey 私钥（用于签名）
     * @return 文件元数据
     */
    public FileMetadata uploadAndEncryptFile(File sourceFile, String password,
                                             boolean shouldSign, PrivateKey privateKey)
            throws Exception {
        log.info("开始处理文件上传: {}", sourceFile.getName());

        String fileId = UUID.randomUUID().toString();
        String encryptedFileName = fileId + ".enc";
        File encryptedFile = new File(Paths.get(baseDir, encryptedDir,
                encryptedFileName).toString());

        // 计算原始文件哈希
        String originalHash = integrityService.calculateFileHash(sourceFile);

        // 加密文件
        EncryptionService.EncryptionMetadata encMeta =
                encryptionService.encryptFile(sourceFile, encryptedFile, password);

        // 创建元数据
        FileMetadata metadata = FileMetadata.builder()
                .fileId(fileId)
                .originalFileName(sourceFile.getName())
                .originalFileSize(sourceFile.length())
                .encryptedFileName(encryptedFileName)
                .encryptedFilePath(encryptedFile.getAbsolutePath())
                .originalFileHash(originalHash)
                .uploadTime(LocalDateTime.now())
                .encrypted(true)
                .build();

        // 如果需要签名
        if (shouldSign && privateKey != null) {
            String signatureFileName = fileId + ".sig";
            File signatureFile = new File(Paths.get(baseDir, signatureDir,
                    signatureFileName).toString());

            // 对原始文件签名
            signatureService.signAndSaveFile(sourceFile, privateKey, signatureFile);

            metadata.setSigned(true);
            metadata.setSignatureFileName(signatureFileName);
            metadata.setSignatureFilePath(signatureFile.getAbsolutePath());
        }

        // 保存元数据
        fileMetadataMap.put(fileId, metadata);

        log.info("文件上传并加密成功: {}", fileId);
        return metadata;
    }

    /**
     * 解密文件
     * @param fileId 文件ID
     * @param password 解密密码
     * @return 解密后的文件
     */
    public File decryptFile(String fileId, String password) throws Exception {
        log.info("开始解密文件: {}", fileId);

        FileMetadata metadata = fileMetadataMap.get(fileId);
        if (metadata == null) {
            throw new IllegalArgumentException("文件不存在: " + fileId);
        }

        File encryptedFile = new File(metadata.getEncryptedFilePath());
        String decryptedFileName = metadata.getOriginalFileName();
        File decryptedFile = new File(Paths.get(baseDir, decryptedDir,
                decryptedFileName).toString());

        // 解密文件
        encryptionService.decryptFile(encryptedFile, decryptedFile, password);

        // 验证完整性
        String decryptedHash = integrityService.calculateFileHash(decryptedFile);
        if (!decryptedHash.equals(metadata.getOriginalFileHash())) {
            log.error("文件完整性验证失败");
            decryptedFile.delete();
            throw new SecurityException("文件完整性验证失败");
        }

        log.info("文件解密成功: {}", decryptedFileName);
        return decryptedFile;
    }

    /**
     * 验证文件签名
     * @param fileId 文件ID
     * @param publicKey 公钥
     * @return 验证结果
     */
    public boolean verifyFileSignature(String fileId, PublicKey publicKey)
            throws Exception {
        log.info("验证文件签名: {}", fileId);

        FileMetadata metadata = fileMetadataMap.get(fileId);
        if (metadata == null || !metadata.isSigned()) {
            throw new IllegalArgumentException("文件不存在或未签名");
        }

        // 首先需要解密文件才能验证签名
        // 这里假设已经解密，或者对加密前的文件进行验证
        File signatureFile = new File(metadata.getSignatureFilePath());

        // 需要原始文件来验证签名，这里使用解密后的文件
        File decryptedFile = new File(Paths.get(baseDir, decryptedDir,
                metadata.getOriginalFileName()).toString());

        if (!decryptedFile.exists()) {
            throw new IllegalStateException("请先解密文件再验证签名");
        }

        return signatureService.loadAndVerifyFile(decryptedFile,
                signatureFile, publicKey);
    }

    /**
     * 获取所有文件元数据
     */
    public List<FileMetadata> getAllFileMetadata() {
        return new ArrayList<>(fileMetadataMap.values());
    }

    /**
     * 获取文件元数据
     */
    public FileMetadata getFileMetadata(String fileId) {
        return fileMetadataMap.get(fileId);
    }

    /**
     * 删除文件
     */
    public void deleteFile(String fileId) throws IOException {
        log.info("删除文件: {}", fileId);

        FileMetadata metadata = fileMetadataMap.get(fileId);
        if (metadata == null) {
            throw new IllegalArgumentException("文件不存在: " + fileId);
        }

        // 删除加密文件
        File encryptedFile = new File(metadata.getEncryptedFilePath());
        if (encryptedFile.exists()) {
            encryptedFile.delete();
        }

        // 删除签名文件
        if (metadata.isSigned()) {
            File signatureFile = new File(metadata.getSignatureFilePath());
            if (signatureFile.exists()) {
                signatureFile.delete();
            }
        }

        // 删除解密文件（如果存在）
        File decryptedFile = new File(Paths.get(baseDir, decryptedDir,
                metadata.getOriginalFileName()).toString());
        if (decryptedFile.exists()) {
            decryptedFile.delete();
        }

        // 删除元数据
        fileMetadataMap.remove(fileId);

        log.info("文件删除成功: {}", fileId);
    }

    /**
     * 获取存储目录信息
     */
    public Map<String, String> getStorageInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("baseDir", baseDir);
        info.put("encryptedDir", Paths.get(baseDir, encryptedDir).toString());
        info.put("decryptedDir", Paths.get(baseDir, decryptedDir).toString());
        info.put("signatureDir", Paths.get(baseDir, signatureDir).toString());
        info.put("totalFiles", String.valueOf(fileMetadataMap.size()));
        return info;
    }
}