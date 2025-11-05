package com.security.filestore.ui;

import com.security.filestore.model.FileMetadata;
import com.security.filestore.service.*;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

/**
 * 主界面窗口
 */
@Slf4j
@Component
public class MainWindow {

    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private KeyManagementService keyManagementService;

    private Stage primaryStage;
    private TableView<FileMetadata> fileTable;
    private ObservableList<FileMetadata> fileList;
    private Label statusLabel;

    // 当前用户的密钥对
    private KeyPair currentKeyPair;
    private KeyStore keyStore;

    public void start(Stage stage) {
        this.primaryStage = stage;
        primaryStage.setTitle("安全文件存储系统");

        // 初始化密钥
        initializeKeys();

        // 创建主布局
        BorderPane root = new BorderPane();
        root.setPadding(new Insets(10));

        // 顶部工具栏
        ToolBar toolBar = createToolBar();
        root.setTop(toolBar);

        // 中央文件列表
        fileTable = createFileTable();
        root.setCenter(fileTable);

        // 底部状态栏
        statusLabel = new Label("就绪");
        HBox statusBar = new HBox(statusLabel);
        statusBar.setPadding(new Insets(5));
        statusBar.setStyle("-fx-background-color: #f0f0f0;");
        root.setBottom(statusBar);

        // 设置拖拽支持
        setupDragAndDrop(root);

        // 创建场景
        Scene scene = new Scene(root, 1000, 600);
        primaryStage.setScene(scene);
        primaryStage.show();

        // 加载文件列表
        refreshFileList();

        updateStatus("系统已启动");
    }

    /**
     * 初始化密钥
     */
    private void initializeKeys() {
        try {
            File keystoreFile = new File("./secure-storage/user.p12");
            String keystorePassword = "keystore123";

            if (keystoreFile.exists()) {
                // 加载现有密钥库
                keyStore = keyManagementService.loadKeyStore(keystoreFile, keystorePassword);
                PrivateKey privateKey = keyManagementService.getPrivateKey(
                        keyStore, "user-key", keystorePassword);
                PublicKey publicKey = keyManagementService.getPublicKey(
                        keyStore, "user-key");
                currentKeyPair = new KeyPair(publicKey, privateKey);
                log.info("已加载现有密钥对");
            } else {
                // 创建新密钥库
                keyStore = keyManagementService.createKeyStore(keystoreFile, keystorePassword);
                currentKeyPair = signatureService.generateKeyPair();
                keyManagementService.storeKeyPairWithCertificate(
                        keyStore, "user-key", currentKeyPair, keystorePassword,
                        "CN=SecureFileUser, O=SecureStorage, C=CN");
                keyManagementService.saveKeyStore(keyStore, keystoreFile, keystorePassword);
                log.info("已创建新密钥对");
            }
        } catch (Exception e) {
            log.error("密钥初始化失败", e);
            showError("密钥初始化失败", e.getMessage());
        }
    }

    /**
     * 创建工具栏
     */
    private ToolBar createToolBar() {
        Button btnUpload = new Button("上传文件");
        btnUpload.setOnAction(e -> handleUploadFile());

        Button btnDecrypt = new Button("解密文件");
        btnDecrypt.setOnAction(e -> handleDecryptFile());

        Button btnVerify = new Button("验证签名");
        btnVerify.setOnAction(e -> handleVerifySignature());

        Button btnDelete = new Button("删除文件");
        btnDelete.setOnAction(e -> handleDeleteFile());

        Button btnKeyManagement = new Button("密钥管理");
        btnKeyManagement.setOnAction(e -> handleKeyManagement());

        Button btnRefresh = new Button("刷新");
        btnRefresh.setOnAction(e -> refreshFileList());

        return new ToolBar(
                btnUpload,
                new Separator(),
                btnDecrypt,
                btnVerify,
                new Separator(),
                btnDelete,
                new Separator(),
                btnKeyManagement,
                btnRefresh
        );
    }

    /**
     * 创建文件表格
     */
    private TableView<FileMetadata> createFileTable() {
        fileList = FXCollections.observableArrayList();
        TableView<FileMetadata> table = new TableView<>(fileList);

        TableColumn<FileMetadata, String> colName = new TableColumn<>("文件名");
        colName.setCellValueFactory(new PropertyValueFactory<>("originalFileName"));
        colName.setPrefWidth(250);

        TableColumn<FileMetadata, String> colSize = new TableColumn<>("大小");
        colSize.setCellValueFactory(cellData ->
                new javafx.beans.property.SimpleStringProperty(
                        cellData.getValue().getFormattedFileSize()));
        colSize.setPrefWidth(100);

        TableColumn<FileMetadata, String> colHash = new TableColumn<>("哈希值");
        colHash.setCellValueFactory(new PropertyValueFactory<>("originalFileHash"));
        colHash.setPrefWidth(300);

        TableColumn<FileMetadata, String> colStatus = new TableColumn<>("安全状态");
        colStatus.setCellValueFactory(cellData ->
                new javafx.beans.property.SimpleStringProperty(
                        cellData.getValue().getSecurityStatus()));
        colStatus.setPrefWidth(150);

        TableColumn<FileMetadata, String> colTime = new TableColumn<>("上传时间");
        colTime.setCellValueFactory(new PropertyValueFactory<>("uploadTime"));
        colTime.setPrefWidth(180);

        table.getColumns().addAll(colName, colSize, colHash, colStatus, colTime);
        return table;
    }

    /**
     * 设置拖拽功能
     */
    private void setupDragAndDrop(BorderPane root) {
        root.setOnDragOver((DragEvent event) -> {
            Dragboard db = event.getDragboard();
            if (db.hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        root.setOnDragDropped((DragEvent event) -> {
            Dragboard db = event.getDragboard();
            boolean success = false;
            if (db.hasFiles()) {
                for (File file : db.getFiles()) {
                    uploadFile(file);
                }
                success = true;
            }
            event.setDropCompleted(success);
            event.consume();
        });
    }

    /**
     * 处理文件上传
     */
    private void handleUploadFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择要上传的文件");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            uploadFile(file);
        }
    }

    /**
     * 上传文件
     */
    private void uploadFile(File file) {
        // 检查文件后缀，如果是.enc文件，则直接进行解密
        String fileName = file.getName().toLowerCase();
        if (fileName.endsWith(".enc")) {
            handleDecryptExternalFile(file);
            return;
        }

        // 创建对话框获取加密密码和选项
        Dialog<UploadOptions> dialog = new Dialog<>();
        dialog.setTitle("文件加密选项");
        dialog.setHeaderText("为文件 " + file.getName() + " 设置加密选项");

        ButtonType uploadButtonType = new ButtonType("上传", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(uploadButtonType, ButtonType.CANCEL);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        PasswordField password = new PasswordField();
        password.setPromptText("加密密码");

        PasswordField confirmPassword = new PasswordField();
        confirmPassword.setPromptText("确认密码");

        CheckBox signCheckBox = new CheckBox("对文件进行数字签名");
        signCheckBox.setSelected(true);

        grid.add(new Label("加密密码:"), 0, 0);
        grid.add(password, 1, 0);
        grid.add(new Label("确认密码:"), 0, 1);
        grid.add(confirmPassword, 1, 1);
        grid.add(signCheckBox, 0, 2, 2, 1);

        dialog.getDialogPane().setContent(grid);

        Platform.runLater(() -> password.requestFocus());

        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == uploadButtonType) {
                if (!password.getText().equals(confirmPassword.getText())) {
                    showError("错误", "两次输入的密码不一致");
                    return null;
                }
                return new UploadOptions(password.getText(), signCheckBox.isSelected());
            }
            return null;
        });

        Optional<UploadOptions> result = dialog.showAndWait();

        result.ifPresent(options -> {
            new Thread(() -> {
                try {
                    updateStatus("正在上传文件: " + file.getName());

                    FileMetadata metadata = fileStorageService.uploadAndEncryptFile(
                            file,
                            options.password,
                            options.shouldSign,
                            options.shouldSign ? currentKeyPair.getPrivate() : null
                    );

                    Platform.runLater(() -> {
                        refreshFileList();
                        updateStatus("文件上传成功: " + file.getName());
                        showInfo("成功", "文件已加密并上传");
                    });
                } catch (Exception e) {
                    log.error("文件上传失败", e);
                    Platform.runLater(() -> {
                        showError("上传失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        });
    }

    /**
     * 处理解密外部加密文件（.enc文件）
     */
    private void handleDecryptExternalFile(File encryptedFile) {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("解密加密文件");
        dialog.setHeaderText("检测到加密文件: " + encryptedFile.getName());
        dialog.setContentText("请输入解密密码:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(password -> {
            new Thread(() -> {
                try {
                    updateStatus("正在解密文件: " + encryptedFile.getName());
                    FileMetadata metadata = fileStorageService.decryptExternalFile(encryptedFile, password);

                    Platform.runLater(() -> {
                        refreshFileList();
                        updateStatus("文件解密成功: " + metadata.getOriginalFileName());
                        showInfo("成功", "文件已解密并添加到文件列表\n解密文件位置: " + metadata.getDecryptedFilePath());
                    });
                } catch (Exception e) {
                    log.error("文件解密失败", e);
                    Platform.runLater(() -> {
                        showError("解密失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        });
    }

    /**
     * 处理文件解密
     */
    private void handleDecryptFile() {
        FileMetadata selected = fileTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showWarning("提示", "请先选择要解密的文件");
            return;
        }

        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("解密文件");
        dialog.setHeaderText("解密文件: " + selected.getOriginalFileName());
        dialog.setContentText("请输入解密密码:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(password -> {
            new Thread(() -> {
                try {
                    updateStatus("正在解密文件...");
                    File decryptedFile = fileStorageService.decryptFile(
                            selected.getFileId(), password);

                    Platform.runLater(() -> {
                        refreshFileList();  // 刷新文件列表以显示更新后的状态
                        updateStatus("文件解密成功: " + decryptedFile.getName());
                        showInfo("成功", "文件已解密到: " + decryptedFile.getAbsolutePath());
                    });
                } catch (Exception e) {
                    log.error("文件解密失败", e);
                    Platform.runLater(() -> {
                        showError("解密失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        });
    }

    /**
     * 处理签名验证
     */
    private void handleVerifySignature() {
        FileMetadata selected = fileTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showWarning("提示", "请先选择要验证的文件");
            return;
        }

        if (!selected.isSigned()) {
            showWarning("提示", "该文件未签名");
            return;
        }

        new Thread(() -> {
            try {
                updateStatus("正在验证签名...");
                boolean valid = fileStorageService.verifyFileSignature(
                        selected.getFileId(), currentKeyPair.getPublic());

                Platform.runLater(() -> {
                    if (valid) {
                        showInfo("验证成功", "文件签名有效，文件完整且来源可信");
                        updateStatus("签名验证通过");
                    } else {
                        showError("验证失败", "文件签名无效，文件可能已被篡改");
                        updateStatus("签名验证失败");
                    }
                });
            } catch (Exception e) {
                log.error("签名验证失败", e);
                Platform.runLater(() -> {
                    showError("验证失败", e.getMessage());
                    updateStatus("就绪");
                });
            }
        }).start();
    }

    /**
     * 处理文件删除
     */
    private void handleDeleteFile() {
        FileMetadata selected = fileTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showWarning("提示", "请先选择要删除的文件");
            return;
        }

        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("确认删除");
        alert.setHeaderText("删除文件: " + selected.getOriginalFileName());
        alert.setContentText("确定要删除这个文件吗？此操作不可恢复。");

        Optional<ButtonType> result = alert.showAndWait();
        if (result.isPresent() && result.get() == ButtonType.OK) {
            try {
                fileStorageService.deleteFile(selected.getFileId());
                refreshFileList();
                updateStatus("文件已删除");
            } catch (Exception e) {
                showError("删除失败", e.getMessage());
            }
        }
    }

    /**
     * 处理密钥管理
     */
    private void handleKeyManagement() {
        // 创建密钥管理对话框
        Stage keyManagementStage = new Stage();
        keyManagementStage.setTitle("密钥管理");
        keyManagementStage.initOwner(primaryStage);
        keyManagementStage.setResizable(true);
        keyManagementStage.setWidth(700);
        keyManagementStage.setHeight(600);

        // 创建标签页
        TabPane tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        // 1. 密钥信息标签页
        Tab infoTab = new Tab("密钥信息");
        infoTab.setContent(createKeyInfoTab(keyManagementStage));
        tabPane.getTabs().add(infoTab);

        // 2. 导出密钥标签页
        Tab exportTab = new Tab("导出密钥");
        exportTab.setContent(createExportKeyTab());
        tabPane.getTabs().add(exportTab);

        // 3. 导入密钥标签页
        Tab importTab = new Tab("导入密钥");
        importTab.setContent(createImportKeyTab());
        tabPane.getTabs().add(importTab);

        // 4. 备份与恢复标签页
        Tab backupTab = new Tab("备份与恢复");
        backupTab.setContent(createBackupTab());
        tabPane.getTabs().add(backupTab);

        // 5. 证书信息标签页
        Tab certTab = new Tab("证书信息");
        certTab.setContent(createCertificateTab());
        tabPane.getTabs().add(certTab);

        VBox root = new VBox(10);
        root.setPadding(new Insets(10));
        root.getChildren().add(tabPane);

        Scene scene = new Scene(root);
        keyManagementStage.setScene(scene);
        keyManagementStage.show();
    }

    /**
     * 创建密钥信息标签页
     */
    private VBox createKeyInfoTab(Stage keyManagementStage) {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(15));

        Label titleLabel = new Label("当前密钥对信息");
        titleLabel.setStyle("-fx-font-size: 14pt; -fx-font-weight: bold;");

        TextArea infoArea = new TextArea();
        infoArea.setEditable(false);
        infoArea.setPrefRowCount(12);
        infoArea.setWrapText(true);

        Button refreshBtn = new Button("刷新信息");
        refreshBtn.setOnAction(e -> {
            try {
                String info = getKeyPairInfo();
                infoArea.setText(info);
            } catch (Exception ex) {
                showError("错误", "获取密钥信息失败: " + ex.getMessage());
            }
        });

        // 初始加载
        refreshBtn.fire();

        Button regenerateBtn = new Button("重新生成密钥对");
        regenerateBtn.setStyle("-fx-background-color: #ff9800; -fx-text-fill: white;");
        regenerateBtn.setOnAction(e -> handleRegenerateKeyPair(keyManagementStage));

        HBox buttonBox = new HBox(10);
        buttonBox.getChildren().addAll(refreshBtn, regenerateBtn);

        vbox.getChildren().addAll(titleLabel, infoArea, buttonBox);
        return vbox;
    }

    /**
     * 获取密钥对信息
     */
    private String getKeyPairInfo() {
        try {
            StringBuilder info = new StringBuilder();
            if (currentKeyPair != null) {
                PublicKey publicKey = currentKeyPair.getPublic();
                PrivateKey privateKey = currentKeyPair.getPrivate();

                info.append("密钥算法: RSA\n");
                info.append("密钥长度: ").append(((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength()).append(" 位\n\n");

                info.append("公钥信息:\n");
                String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                info.append("  格式: ").append(publicKey.getFormat()).append("\n");
                info.append("  长度: ").append(publicKeyBase64.length()).append(" 字符 (Base64)\n");
                info.append("  前64字符: ").append(publicKeyBase64.substring(0, Math.min(64, publicKeyBase64.length()))).append("...\n\n");

                info.append("私钥信息:\n");
                info.append("  格式: ").append(privateKey.getFormat()).append("\n");
                info.append("  算法: ").append(privateKey.getAlgorithm()).append("\n\n");

                File keystoreFile = new File("./secure-storage/user.p12");
                if (keystoreFile.exists()) {
                    info.append("密钥库位置: ").append(keystoreFile.getAbsolutePath()).append("\n");
                    info.append("密钥库大小: ").append(keystoreFile.length()).append(" 字节\n");
                    info.append("密钥库类型: PKCS12\n");
                }
            } else {
                info.append("当前没有可用的密钥对");
            }
            return info.toString();
        } catch (Exception e) {
            return "获取密钥信息失败: " + e.getMessage();
        }
    }

    /**
     * 创建导出密钥标签页
     */
    private VBox createExportKeyTab() {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(15));

        // 导出公钥
        TitledPane publicKeyGroup = new TitledPane("导出公钥", null);
        publicKeyGroup.setCollapsible(false);
        VBox publicKeyBox = new VBox(10);
        publicKeyBox.setPadding(new Insets(10));

        Label publicKeyLabel = new Label("将公钥导出为PEM格式文件");
        Button exportPublicBtn = new Button("导出公钥");
        exportPublicBtn.setOnAction(e -> handleExportPublicKey());
        publicKeyBox.getChildren().addAll(publicKeyLabel, exportPublicBtn);
        publicKeyGroup.setContent(publicKeyBox);

        // 导出私钥
        TitledPane privateKeyGroup = new TitledPane("导出私钥（加密）", null);
        privateKeyGroup.setCollapsible(false);
        VBox privateKeyBox = new VBox(10);
        privateKeyBox.setPadding(new Insets(10));

        Label privateKeyLabel = new Label("将私钥导出为加密文件（需要设置密码）");
        Label privateKeyWarnLabel = new Label("⚠ 私钥非常重要，请妥善保管！");
        privateKeyWarnLabel.setStyle("-fx-text-fill: red;");
        Button exportPrivateBtn = new Button("导出私钥");
        exportPrivateBtn.setOnAction(e -> handleExportPrivateKey());
        privateKeyBox.getChildren().addAll(privateKeyLabel, privateKeyWarnLabel, exportPrivateBtn);
        privateKeyGroup.setContent(privateKeyBox);

        vbox.getChildren().addAll(publicKeyGroup, privateKeyGroup);
        return vbox;
    }

    /**
     * 创建导入密钥标签页
     */
    private VBox createImportKeyTab() {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(15));

        // 导入公钥
        TitledPane importPublicGroup = new TitledPane("导入公钥", null);
        importPublicGroup.setCollapsible(false);
        VBox importPublicBox = new VBox(10);
        importPublicBox.setPadding(new Insets(10));

        Label importPublicLabel = new Label("从PEM格式文件导入公钥");
        Button importPublicBtn = new Button("导入公钥");
        importPublicBtn.setOnAction(e -> handleImportPublicKey());
        importPublicBox.getChildren().addAll(importPublicLabel, importPublicBtn);
        importPublicGroup.setContent(importPublicBox);

        // 导入私钥
        TitledPane importPrivateGroup = new TitledPane("导入私钥（加密文件）", null);
        importPrivateGroup.setCollapsible(false);
        VBox importPrivateBox = new VBox(10);
        importPrivateBox.setPadding(new Insets(10));

        Label importPrivateLabel = new Label("从加密文件导入私钥（需要提供加密密码）");
        Button importPrivateBtn = new Button("导入私钥");
        importPrivateBtn.setOnAction(e -> handleImportPrivateKey());
        importPrivateBox.getChildren().addAll(importPrivateLabel, importPrivateBtn);
        importPrivateGroup.setContent(importPrivateBox);

        vbox.getChildren().addAll(importPublicGroup, importPrivateGroup);
        return vbox;
    }

    /**
     * 创建备份与恢复标签页
     */
    private VBox createBackupTab() {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(15));

        Label titleLabel = new Label("密钥库备份与恢复");
        titleLabel.setStyle("-fx-font-size: 12pt; -fx-font-weight: bold;");

        TextArea backupInfoArea = new TextArea();
        backupInfoArea.setEditable(false);
        backupInfoArea.setPrefRowCount(5);
        backupInfoArea.setWrapText(true);
        backupInfoArea.setText("备份功能说明:\n" +
                "1. 备份会将整个密钥库文件复制到指定位置\n" +
                "2. 备份文件包含所有密钥和证书\n" +
                "3. 恢复时需要提供正确的密钥库密码");

        Button backupBtn = new Button("备份密钥库");
        backupBtn.setStyle("-fx-background-color: #4CAF50; -fx-text-fill: white;");
        backupBtn.setOnAction(e -> handleBackupKeyStore());

        Button restoreBtn = new Button("从备份恢复");
        restoreBtn.setStyle("-fx-background-color: #2196F3; -fx-text-fill: white;");
        restoreBtn.setOnAction(e -> handleRestoreKeyStore());

        vbox.getChildren().addAll(titleLabel, backupInfoArea, backupBtn, restoreBtn);
        return vbox;
    }

    /**
     * 创建证书信息标签页
     */
    private VBox createCertificateTab() {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(15));

        Label titleLabel = new Label("证书信息");
        titleLabel.setStyle("-fx-font-size: 12pt; -fx-font-weight: bold;");

        TextArea certArea = new TextArea();
        certArea.setEditable(false);
        certArea.setPrefRowCount(15);
        certArea.setWrapText(true);

        Button viewCertBtn = new Button("查看证书信息");
        viewCertBtn.setOnAction(e -> {
            try {
                if (keyStore != null) {
                    X509Certificate cert = keyManagementService.getCertificate(keyStore, "user-key");
                    String certInfo = keyManagementService.getCertificateInfo(cert);
                    certArea.setText(certInfo);
                } else {
                    certArea.setText("请先加载密钥库");
                }
            } catch (Exception ex) {
                showError("错误", "获取证书信息失败: " + ex.getMessage());
            }
        });

        Button verifyCertBtn = new Button("验证证书");
        verifyCertBtn.setOnAction(e -> {
            try {
                if (keyStore != null) {
                    X509Certificate cert = keyManagementService.getCertificate(keyStore, "user-key");
                    boolean isValid = keyManagementService.verifyCertificate(cert);
                    if (isValid) {
                        showInfo("验证成功", "证书有效且签名正确");
                    } else {
                        showWarning("验证失败", "证书无效或已过期");
                    }
                } else {
                    showWarning("提示", "请先加载密钥库");
                }
            } catch (Exception ex) {
                showError("错误", "验证证书失败: " + ex.getMessage());
            }
        });

        HBox buttonBox = new HBox(10);
        buttonBox.getChildren().addAll(viewCertBtn, verifyCertBtn);

        vbox.getChildren().addAll(titleLabel, certArea, buttonBox);
        return vbox;
    }

    /**
     * 处理导出公钥
     */
    private void handleExportPublicKey() {
        if (currentKeyPair == null) {
            showWarning("提示", "当前没有可用的密钥对");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择公钥保存位置");
        fileChooser.setInitialFileName("public_key.pem");
        File file = fileChooser.showSaveDialog(primaryStage);

        if (file != null) {
            new Thread(() -> {
                try {
                    updateStatus("正在导出公钥...");
                    keyManagementService.exportPublicKey(currentKeyPair.getPublic(), file);
                    Platform.runLater(() -> {
                        showInfo("成功", "公钥已导出到: " + file.getAbsolutePath());
                        updateStatus("公钥导出成功");
                    });
                } catch (Exception e) {
                    log.error("导出公钥失败", e);
                    Platform.runLater(() -> {
                        showError("导出失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        }
    }

    /**
     * 处理导出私钥
     */
    private void handleExportPrivateKey() {
        if (currentKeyPair == null) {
            showWarning("提示", "当前没有可用的密钥对");
            return;
        }

        // 创建密码输入对话框
        Dialog<String> dialog = new Dialog<>();
        dialog.setTitle("导出私钥");
        dialog.setHeaderText("为私钥文件设置加密密码");

        ButtonType exportButtonType = new ButtonType("导出", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(exportButtonType, ButtonType.CANCEL);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        PasswordField password = new PasswordField();
        password.setPromptText("加密密码");
        PasswordField confirmPassword = new PasswordField();
        confirmPassword.setPromptText("确认密码");

        grid.add(new Label("加密密码:"), 0, 0);
        grid.add(password, 1, 0);
        grid.add(new Label("确认密码:"), 0, 1);
        grid.add(confirmPassword, 1, 1);

        dialog.getDialogPane().setContent(grid);
        Platform.runLater(() -> password.requestFocus());

        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == exportButtonType) {
                if (!password.getText().equals(confirmPassword.getText())) {
                    showError("错误", "两次输入的密码不一致");
                    return null;
                }
                if (password.getText().isEmpty()) {
                    showError("错误", "密码不能为空");
                    return null;
                }
                return password.getText();
            }
            return null;
        });

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(pwd -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("选择私钥保存位置");
            fileChooser.setInitialFileName("private_key.enc");
            File file = fileChooser.showSaveDialog(primaryStage);

            if (file != null) {
                new Thread(() -> {
                    try {
                        updateStatus("正在导出私钥...");
                        keyManagementService.exportPrivateKey(currentKeyPair.getPrivate(), file, pwd);
                        Platform.runLater(() -> {
                            showInfo("成功", "私钥已导出到: " + file.getAbsolutePath());
                            updateStatus("私钥导出成功");
                        });
                    } catch (Exception e) {
                        log.error("导出私钥失败", e);
                        Platform.runLater(() -> {
                            showError("导出失败", e.getMessage());
                            updateStatus("就绪");
                        });
                    }
                }).start();
            }
        });
    }

    /**
     * 处理导入公钥
     */
    private void handleImportPublicKey() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择公钥文件");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PEM文件", "*.pem", "*.key", "*.pub"));
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            new Thread(() -> {
                try {
                    updateStatus("正在导入公钥...");
                    PublicKey publicKey = keyManagementService.importPublicKey(file);
                    
                    // 询问是否替换当前密钥对
                    Platform.runLater(() -> {
                        Alert confirmAlert = new Alert(Alert.AlertType.CONFIRMATION);
                        confirmAlert.setTitle("确认");
                        confirmAlert.setHeaderText("导入公钥成功");
                        confirmAlert.setContentText("是否使用导入的公钥替换当前密钥对？\n注意：这将导致无法使用原来的私钥进行签名。");
                        
                        Optional<ButtonType> result = confirmAlert.showAndWait();
                        if (result.isPresent() && result.get() == ButtonType.OK) {
                            // 保留原私钥，只更新公钥
                            PrivateKey privateKey = currentKeyPair != null ? currentKeyPair.getPrivate() : null;
                            if (privateKey != null) {
                                currentKeyPair = new KeyPair(publicKey, privateKey);
                                updateStatus("公钥已更新");
                            } else {
                                showWarning("提示", "无法创建完整的密钥对，因为没有私钥");
                            }
                        }
                        updateStatus("公钥导入成功");
                    });
                } catch (Exception e) {
                    log.error("导入公钥失败", e);
                    Platform.runLater(() -> {
                        showError("导入失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        }
    }

    /**
     * 处理导入私钥
     */
    private void handleImportPrivateKey() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择私钥文件");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("加密私钥文件", "*.enc", "*.key"));
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            TextInputDialog passwordDialog = new TextInputDialog();
            passwordDialog.setTitle("输入密码");
            passwordDialog.setHeaderText("请输入私钥文件的解密密码");
            passwordDialog.setContentText("密码:");

            Optional<String> password = passwordDialog.showAndWait();
            password.ifPresent(pwd -> {
                new Thread(() -> {
                    try {
                        updateStatus("正在导入私钥...");
                        PrivateKey privateKey = keyManagementService.importPrivateKey(file, pwd);
                        
                        Platform.runLater(() -> {
                            // 保留原公钥，更新私钥
                            PublicKey publicKey = currentKeyPair != null ? currentKeyPair.getPublic() : null;
                            if (publicKey != null) {
                                currentKeyPair = new KeyPair(publicKey, privateKey);
                            } else {
                                showWarning("提示", "无法创建完整的密钥对，因为没有公钥");
                            }
                            
                            // 更新密钥库
                            try {
                                File keystoreFile = new File("./secure-storage/user.p12");
                                String keystorePassword = "keystore123";
                                
                                if (!keystoreFile.exists()) {
                                    keyStore = keyManagementService.createKeyStore(keystoreFile, keystorePassword);
                                }
                                
                                keyManagementService.storeKeyPairWithCertificate(
                                        keyStore, "user-key", currentKeyPair,
                                        keystorePassword, "CN=SecureFileUser, O=SecureStorage, C=CN");
                                keyManagementService.saveKeyStore(keyStore, keystoreFile, keystorePassword);
                                
                                showInfo("成功", "私钥已导入并更新密钥库");
                                updateStatus("私钥导入成功");
                            } catch (Exception ex) {
                                log.error("更新密钥库失败", ex);
                                showError("错误", "导入私钥成功，但更新密钥库失败: " + ex.getMessage());
                            }
                        });
                    } catch (Exception e) {
                        log.error("导入私钥失败", e);
                        Platform.runLater(() -> {
                            showError("导入失败", "密码错误或文件格式不正确");
                            updateStatus("就绪");
                        });
                    }
                }).start();
            });
        }
    }

    /**
     * 处理备份密钥库
     */
    private void handleBackupKeyStore() {
        File keystoreFile = new File("./secure-storage/user.p12");
        if (!keystoreFile.exists()) {
            showWarning("提示", "密钥库文件不存在");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择备份位置");
        fileChooser.setInitialFileName("user_backup_" + System.currentTimeMillis() + ".p12");
        File backupFile = fileChooser.showSaveDialog(primaryStage);

        if (backupFile != null) {
            new Thread(() -> {
                try {
                    updateStatus("正在备份密钥库...");
                    keyManagementService.backupKeyStore(keystoreFile, backupFile);
                    Platform.runLater(() -> {
                        showInfo("成功", "密钥库已备份到: " + backupFile.getAbsolutePath());
                        updateStatus("密钥库备份成功");
                    });
                } catch (Exception e) {
                    log.error("备份密钥库失败", e);
                    Platform.runLater(() -> {
                        showError("备份失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        }
    }

    /**
     * 处理从备份恢复密钥库
     */
    private void handleRestoreKeyStore() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("选择备份文件");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("密钥库文件", "*.p12", "*.pfx"));
        File backupFile = fileChooser.showOpenDialog(primaryStage);

        if (backupFile != null) {
            Alert confirmAlert = new Alert(Alert.AlertType.CONFIRMATION);
            confirmAlert.setTitle("确认恢复");
            confirmAlert.setHeaderText("恢复密钥库");
            confirmAlert.setContentText("恢复密钥库将替换当前的密钥库。\n请确保已备份当前密钥库！\n是否继续？");

            Optional<ButtonType> result = confirmAlert.showAndWait();
            if (result.isPresent() && result.get() == ButtonType.OK) {
                try {
                    File keystoreFile = new File("./secure-storage/user.p12");
                    keyManagementService.backupKeyStore(backupFile, keystoreFile);
                    
                    // 重新加载密钥库
                    String keystorePassword = "keystore123";
                    keyStore = keyManagementService.loadKeyStore(keystoreFile, keystorePassword);
                    PrivateKey privateKey = keyManagementService.getPrivateKey(
                            keyStore, "user-key", keystorePassword);
                    PublicKey publicKey = keyManagementService.getPublicKey(
                            keyStore, "user-key");
                    currentKeyPair = new KeyPair(publicKey, privateKey);
                    
                    showInfo("成功", "密钥库已恢复");
                    updateStatus("密钥库恢复成功");
                } catch (Exception e) {
                    log.error("恢复密钥库失败", e);
                    showError("恢复失败", e.getMessage());
                }
            }
        }
    }

    /**
     * 处理重新生成密钥对
     */
    private void handleRegenerateKeyPair(Stage keyManagementStage) {
        Alert confirmAlert = new Alert(Alert.AlertType.CONFIRMATION);
        confirmAlert.setTitle("确认重新生成");
        confirmAlert.setHeaderText("重新生成密钥对");
        confirmAlert.setContentText("重新生成密钥对将替换当前密钥对。\n" +
                "所有使用旧密钥对签名的文件将无法验证！\n" +
                "请确保已备份当前密钥库！\n\n是否继续？");

        Optional<ButtonType> result = confirmAlert.showAndWait();
        if (result.isPresent() && result.get() == ButtonType.OK) {
            new Thread(() -> {
                try {
                    updateStatus("正在生成新的密钥对...");
                    KeyPair newKeyPair = signatureService.generateKeyPair();
                    
                    // 更新密钥库
                    File keystoreFile = new File("./secure-storage/user.p12");
                    String keystorePassword = "keystore123";
                    
                    if (!keystoreFile.exists()) {
                        keyStore = keyManagementService.createKeyStore(keystoreFile, keystorePassword);
                    }
                    
                    keyManagementService.storeKeyPairWithCertificate(
                            keyStore, "user-key", newKeyPair,
                            keystorePassword, "CN=SecureFileUser, O=SecureStorage, C=CN");
                    keyManagementService.saveKeyStore(keyStore, keystoreFile, keystorePassword);
                    
                    currentKeyPair = newKeyPair;
                    
                    Platform.runLater(() -> {
                        showInfo("成功", "密钥对已重新生成");
                        updateStatus("密钥对生成成功");
                        keyManagementStage.close();
                    });
                } catch (Exception e) {
                    log.error("重新生成密钥对失败", e);
                    Platform.runLater(() -> {
                        showError("生成失败", e.getMessage());
                        updateStatus("就绪");
                    });
                }
            }).start();
        }
    }

    /**
     * 刷新文件列表
     */
    private void refreshFileList() {
        fileList.clear();
        fileList.addAll(fileStorageService.getAllFileMetadata());
    }

    /**
     * 更新状态栏
     */
    private void updateStatus(String message) {
        Platform.runLater(() -> statusLabel.setText(message));
    }

    /**
     * 显示信息对话框
     */
    private void showInfo(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    /**
     * 显示警告对话框
     */
    private void showWarning(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    /**
     * 显示错误对话框
     */
    private void showError(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    /**
     * 上传选项内部类
     */
    private static class UploadOptions {
        String password;
        boolean shouldSign;

        UploadOptions(String password, boolean shouldSign) {
            this.password = password;
            this.shouldSign = shouldSign;
        }
    }
}