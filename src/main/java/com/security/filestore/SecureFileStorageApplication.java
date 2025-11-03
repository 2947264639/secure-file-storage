package com.security.filestore;

import com.security.filestore.ui.MainWindow;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * 安全文件存储系统主应用
 */
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
public class SecureFileStorageApplication extends Application {

    private ConfigurableApplicationContext springContext;
    private MainWindow mainWindow;

    public static void main(String[] args) {
        // 启动JavaFX应用
        launch(args);
    }

    @Override
    public void init() throws Exception {
        // 初始化Spring上下文（不启动Web服务器）
        SpringApplication app = new SpringApplication(SecureFileStorageApplication.class);
        app.setWebApplicationType(org.springframework.boot.WebApplicationType.NONE);
        springContext = app.run();
        mainWindow = springContext.getBean(MainWindow.class);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        // 启动主窗口
        mainWindow.start(primaryStage);
    }

    @Override
    public void stop() throws Exception {
        // 关闭Spring上下文
        springContext.close();
        Platform.exit();
    }
}