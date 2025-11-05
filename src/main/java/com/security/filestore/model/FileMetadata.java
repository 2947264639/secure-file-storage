package com.security.filestore.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 文件元数据模型
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileMetadata {

    // 文件ID
    private String fileId;

    // 原始文件信息
    private String originalFileName;
    private Long originalFileSize;
    private String originalFileHash;

    // 加密文件信息
    private String encryptedFileName;
    private String encryptedFilePath;
    private boolean encrypted;

    // 签名信息
    private boolean signed;
    private String signatureFileName;
    private String signatureFilePath;

    // 解密信息
    private boolean decrypted;
    private String decryptedFilePath;

    // 时间戳
    private LocalDateTime uploadTime;
    private LocalDateTime lastAccessTime;

    // 备注
    private String description;

    /**
     * 格式化文件大小
     */
    public String getFormattedFileSize() {
        if (originalFileSize == null) {
            return "N/A";
        }

        long size = originalFileSize;
        if (size < 1024) {
            return size + " B";
        } else if (size < 1024 * 1024) {
            return String.format("%.2f KB", size / 1024.0);
        } else if (size < 1024 * 1024 * 1024) {
            return String.format("%.2f MB", size / (1024.0 * 1024));
        } else {
            return String.format("%.2f GB", size / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * 获取安全状态描述
     */
    public String getSecurityStatus() {
        StringBuilder status = new StringBuilder();

        if (decrypted) {
            // 如果已解密，优先显示"已解密"，不显示"已加密"
            status.append("已解密");
        } else if (encrypted) {
            // 只有在未解密时才显示"已加密"
            status.append("已加密");
        }

        if (signed) {
            if (status.length() > 0) {
                status.append(" | ");
            }
            status.append("已签名");
        }

        return status.length() > 0 ? status.toString() : "未保护";
    }
}