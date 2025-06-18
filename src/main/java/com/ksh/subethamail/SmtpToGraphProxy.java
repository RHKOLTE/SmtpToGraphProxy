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

import com.ksh.subethamail.util.ConfigUtils;
import com.ksh.subethamail.util.GraphEmailSender;
import com.ksh.subethamail.util.MimeMessageLogger;
import com.ksh.subethamail.util.MyCustomSSLFactory;
import com.ksh.subethamail.util.SimpleAuthHandlerFactory;

public class SmtpToGraphProxy {

    private static final Logger log = LoggerFactory.getLogger(SmtpToGraphProxy.class);

    public static void main(String[] args) {
        log.info("Starting SmtpToGraphProxy");
        System.out.println("Starting SmtpToGraphProxy");
        String configFilePath = "";
        Properties config=null;
        try {
            configFilePath = ConfigUtils.parseArgs(args);
            if (configFilePath == null) {
                System.err.println("Missing -config argument");
                System.exit(1);
            }

            config = ConfigUtils.loadConfig(configFilePath);
            // Continue with your app logic...
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        try {
            System.out.println("Done loadConfig");
            GraphEmailSender.init(
                config.getProperty("o365.clientId"),
                config.getProperty("o365.clientSec"),
                config.getProperty("o365.tenantId"),
                config.getProperty("o365.username"),
                config.getProperty("o365.password"),
                config.getProperty("o365.CredentialType"),
                config.getProperty("o365.SaveToSentItems")
            );
            log.info("Graph client init done");
            System.out.println("Done GraphEmailSender.init");

            MyCustomSSLFactory.initializeSSLContext();
            System.out.println("Done MyCustomSSLFactory.initializeSSLContext");

            SMTPServer server = initializeSmtpServer(config);
            server.start();
            System.out.println("Done SMTPServer started on port:" +config.getProperty("smtp.port"));
            log.info("SMTP to Graph Proxy is running on port {}", config.getProperty("smtp.port"));
        } catch (Exception e) {
            log.error("Failed to start proxy: {}", e.getMessage(), e);
            System.exit(2);
        }
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
                log.error("Failed to send email", ex);
                System.out.println("Failed to send email using Graph for user:"+from);
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
