package com.ksh.subethamail;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.net.ssl.SSLSocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.subethamail.smtp.MessageContext;
import org.subethamail.smtp.MessageHandler;
import org.subethamail.smtp.MessageHandlerFactory;
import org.subethamail.smtp.RejectException;
import org.subethamail.smtp.server.SMTPServer;

import com.ksh.subethamail.util.GraphEmailSender;
import com.ksh.subethamail.util.MimeMessageLogger;
import com.ksh.subethamail.util.MyCustomSSLFactory;
import com.ksh.subethamail.util.SimpleAuthHandlerFactory;

public class SmtpToGraphProxy {

    private static final Logger log = LoggerFactory.getLogger(SmtpToGraphProxy.class);

    public static void main(String[] args) {
        log.info("Starting SmtpToGraphProxy");
        System.out.println("Starting SmtpToGraphProxy");
        String configFilePath = parseArgs(args);
        if (configFilePath == null) {
            log.error("Configuration file path not provided. Use -config <path>");
            System.out.println("Configuration file path not provided. Use -config <path>");
            System.exit(1);
        }

        try {
            Properties config = loadConfig(configFilePath);
            System.out.println("Done loadConfig");
            GraphEmailSender.init(
                config.getProperty("o365.clientId"),
                config.getProperty("o365.tenantId"),
                config.getProperty("o365.username"),
                config.getProperty("o365.password")
            );
            log.info("Graph client init done");
            System.out.println("Done GraphEmailSender.init");

            MyCustomSSLFactory.initializeSSLContext();
            System.out.println("Done MyCustomSSLFactory.initializeSSLContext");

            SMTPServer server = initializeSmtpServer(config);
            server.start();
            System.out.println("Done SMTPServer started on port:" +config.getProperty("smtp.port"));
            log.info("SMTP to Graph Proxy is running on port {}", config.getProperty("smtp.port"));
        } catch (IOException e) {
            log.error("Failed to start proxy: {}", e.getMessage(), e);
            System.exit(2);
        }
    }

    private static String parseArgs(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("-config".equals(args[i])) {
                log.info("Using config file: {}", args[i + 1]);
                return args[i + 1];
            }
        }
        return null;
    }

    private static Properties loadConfig(String fileName) throws IOException {
        Properties props = new Properties();
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName)) {
            if (input == null) {
                throw new FileNotFoundException("Properties file not found in classpath: " + fileName);
            }
            props.load(input);
        }
        return props;
    }

    private static SMTPServer initializeSmtpServer(Properties config) {
        SMTPServer server = new SMTPServer(new GraphMessageHandlerFactory()) {
            @Override
            public SSLSocket createSSLSocket(Socket socket) throws IOException {
                return MyCustomSSLFactory.createSSLSocket(socket);
            }
        };

        server.setPort(Integer.parseInt(config.getProperty("smtp.port")));
        server.setHostName(config.getProperty("smtp.host"));
        server.setSoftwareName("SMTPToGraphProxy");
        server.setConnectionTimeout(Integer.parseInt(config.getProperty("smtp.connection.timeout", "60000")));

        configureTls(server, config);
        configureAuthentication(server, config);

        return server;
    }

    private static void configureTls(SMTPServer server, Properties config) {
        boolean useStartTls = Boolean.parseBoolean(config.getProperty("smtp.useStartTls"));
        server.setEnableTLS(useStartTls);
        server.setRequireTLS(useStartTls);
        server.setHideTLS(!useStartTls);
    }

    private static void configureAuthentication(SMTPServer server, Properties config) {
        String user = config.getProperty("smtp.user");
        String pwd = config.getProperty("smtp.password");
        if (user != null && pwd != null) {
            server.setAuthenticationHandlerFactory(new SimpleAuthHandlerFactory(user, pwd));
        } else {
            log.warn("SMTP authentication not configured.");
        }
    }

    // MessageHandlerFactory
    public static class GraphMessageHandlerFactory implements MessageHandlerFactory {
        @Override
        public MessageHandler create(MessageContext ctx) {
            return new GraphMessageHandler(ctx);
        }
    }

    // Actual message handler
    public static class GraphMessageHandler implements MessageHandler {
        private final MessageContext ctx;
        private String from;
        private final List<String> recipients = new ArrayList<>();

        public GraphMessageHandler(MessageContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public void from(String from) {
            this.from = from;
        }

        @Override
        public void recipient(String recipient) {
            recipients.add(recipient);
        }

        @Override
        public void data(InputStream data) {
            try {
                Session session = Session.getDefaultInstance(new Properties());

                MimeMessage mimeMessage = new MimeMessage(session, data);
        		
                if (log.isDebugEnabled()) {
                    MimeMessageLogger.logMimeMessage(mimeMessage);
        		}
                
                recipients.forEach(rcpt -> log.info(">> Recipient: {}", rcpt));
                System.out.println("Received message from:"+from);
                GraphEmailSender.sendEmail(from, recipients, mimeMessage);
                log.info("Successfully sent email from {}", from);
            } catch (Exception ex) {
                log.error("Failed to process/send email", ex);
                throw new RejectException(554, "Failed to send email: " + ex.getMessage());
            }
        }

        @Override
        public void done() {
            log.info("Finished processing message from: {}", from);
            System.out.println("Finished processing message from:"+from);
        }
    }
}
