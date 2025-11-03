# 安全文件存储系统

## 项目简介

这是一个基于Java的安全文件存储系统，提供文件加密、数字签名、完整性验证等功能，确保用户数据的安全性和可靠性。

## 核心功能

### 1. 文件加密与解密
- **AES-256加密**：采用业界标准的AES加密算法，密钥长度256位
- **CBC模式**：使用CBC工作模式，增强安全性
- **PBKDF2密钥派生**：从用户密码安全派生加密密钥，使用65536次迭代
- **随机盐值和IV**：每次加密使用不同的盐值和初始化向量

### 2. 完整性验证
- **SHA-1哈希**：满足课题要求的SHA-1哈希算法
- **SHA-256增强哈希**：提供更强的哈希算法选项
- **文件完整性检查**：加密前后自动计算并验证文件哈希值

### 3. 数字签名
- **RSA-2048签名**：使用2048位RSA密钥对文件进行数字签名
- **SHA256withRSA算法**：签名算法采用SHA-256哈希配合RSA
- **签名验证**：支持对文件签名的验证，确保文件来源可信

### 4. 密钥管理
- **PKCS12密钥库**：使用标准PKCS12格式存储密钥
- **自签名证书**：自动生成X.509自签名证书
- **密钥导出/导入**：支持公钥和私钥的安全导出和导入
- **密钥备份**：支持密钥库的备份功能
- **加密存储私钥**：导出的私钥使用AES加密保护

### 5. 用户界面
- **JavaFX桌面应用**：友好的图形界面
- **文件拖拽支持**：支持直接拖拽文件到窗口进行上传
- **文件列表管理**：表格形式展示所有文件及其安全状态
- **实时状态显示**：底部状态栏实时显示操作进度

## 技术栈

- **Java 17**：核心编程语言
- **Spring Boot 3.2（非Web）**：应用框架（桌面应用仅用作容器，不启动Web服务器）
- **JavaFX 17.0.2**：图形界面（与 JDK 17 兼容）
- **Bouncy Castle 1.76**：加密算法库
- **H2 Database**：元数据存储
- **Maven**：项目构建工具

## 项目结构

```
secure-file-storage/
├── src/main/java/com/security/filestore/
│   ├── SecureFileStorageApplication.java    # 主程序入口
│   ├── service/
│   │   ├── EncryptionService.java          # 加密服务
│   │   ├── SignatureService.java           # 签名服务
│   │   ├── IntegrityService.java           # 完整性服务
│   │   ├── KeyManagementService.java       # 密钥管理
│   │   └── FileStorageService.java         # 文件存储
│   ├── model/
│   │   └── FileMetadata.java               # 文件元数据
│   └── ui/
│       └── MainWindow.java                  # 主界面
├── src/main/resources/
│   └── application.properties               # 配置文件
├── secure-storage/                          # 数据存储目录（运行时生成）
│   ├── encrypted/                           # 加密文件
│   ├── decrypted/                           # 解密文件
│   ├── signatures/                          # 数字签名
│   └── user.p12                             # 密钥库
└── pom.xml                                  # Maven配置
```

## 安装与运行

### 前置要求
- JDK 17 或更高版本
- Maven 3.6 或更高版本

### 构建项目
```bash
mvn clean install
```

### 运行应用
```bash
mvn -q javafx:run
```

或者直接运行打包后的JAR文件：
```bash
java -jar target/secure-file-storage-0.0.1-SNAPSHOT.jar
```

## 使用指南

### 1. 上传和加密文件

**方式一：点击"上传文件"按钮**
1. 点击工具栏的"上传文件"按钮
2. 在文件选择器中选择要上传的文件
3. 在弹出的对话框中设置加密密码
4. 选择是否对文件进行数字签名
5. 点击"上传"完成操作

**方式二：拖拽文件**
1. 直接将文件拖拽到应用窗口
2. 按照提示设置加密选项

### 2. 解密文件

1. 在文件列表中选择要解密的文件
2. 点击"解密文件"按钮
3. 输入加密时使用的密码
4. 解密后的文件保存在 `secure-storage/decrypted/` 目录

### 3. 验证签名

1. 在文件列表中选择已签名的文件
2. 先解密文件（签名验证需要解密后的文件）
3. 点击"验证签名"按钮
4. 系统自动使用公钥验证签名

### 4. 密钥管理

- 系统启动时自动生成RSA密钥对
- 密钥存储在 `secure-storage/user.p12` 密钥库中
- 点击"密钥管理"按钮打开密钥管理对话框（信息/导出/导入/备份/证书）
- 可导出公钥分享给他人进行签名验证；私钥导出为加密文件

### 5. 删除文件

1. 选择要删除的文件
2. 点击"删除文件"按钮
3. 确认删除操作
4. 系统自动删除加密文件、签名文件和解密文件

## 安全特性

### 1. 加密安全性
- **AES-256**：军用级加密强度
- **随机盐值**：防止彩虹表攻击
- **PBKDF2**：65536次迭代，防止暴力破解
- **随机IV**：每次加密使用不同的初始化向量

### 2. 密钥安全性
- **RSA-2048**：足够的密钥长度
- **PKCS12密钥库**：密码保护的密钥存储
- **加密导出**：私钥导出时使用AES加密

### 3. 完整性保障
- **哈希验证**：加密前后自动验证文件哈希
- **数字签名**：RSA签名确保文件未被篡改
- **错误检测**：解密失败自动清理文件

## 配置说明

### 存储路径配置
在 `application.properties` 中可配置存储路径：

```properties
storage.base-dir=./secure-storage      # 基础目录
storage.encrypted-dir=encrypted        # 加密文件目录
storage.decrypted-dir=decrypted        # 解密文件目录
storage.signature-dir=signatures       # 签名文件目录
```

### 日志配置
```properties
logging.level.root=INFO
logging.level.com.security.filestore=DEBUG
logging.file.name=./secure-storage/logs/application.log
```



## 安全建议

1. **密码强度**：使用至少12位包含大小写字母、数字和符号的密码
2. **密钥备份**：定期备份密钥库文件
3. **访问控制**：限制对存储目录的访问权限
4. **定期更新**：及时更新依赖库以修复安全漏洞
5. **密码管理**：不要将密码明文保存或共享

## 测试

运行单元测试：
```bash
mvn test
```

## 课题要求对照

| 要求 | 实现情况 | 说明 |
|------|---------|------|
| 支持AES加密 | ✅ | AES-256/CBC/PKCS5Padding |
| 支持SHA-1哈希 | ✅ | IntegrityService |
| 口令生成密钥 | ✅ | PBKDF2密钥派生 |
| 保存为独立文件 | ✅ | .enc格式加密文件 |
| RSA数字签名 | ✅ | SHA256withRSA |
| 签名认证服务 | ✅ | SignatureService |
| 密钥管理 | ✅ | PKCS12密钥库、导出/导入/备份 |
| 友好界面 | ✅ | JavaFX图形界面 |
| 文件拖拽 | ✅ | 支持拖拽上传 |
| Java技术栈 | ✅ | Java 17 + Spring Boot |
| 本地文件操作 | ✅ | 预设目录结构 |

## 许可证

MIT License

## 作者

安全文件存储系统开发团队

## 联系方式

如有问题或建议，请通过以下方式联系：
- 项目Issues
- Email: support@securefilestorage.com