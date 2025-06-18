package com.ksh.subethamail.util;

import com.ksh.subethamail.SmtpToGraphProxy;
import com.microsoft.aad.msal4j.*;

import java.util.Collections;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DeviceCodeAuth {
    private static final Logger log = LoggerFactory.getLogger(DeviceCodeAuth.class);

    public static void main(String[] args) throws Exception {
        log.info("Starting DeviceCodeAuth");
        System.out.println("Starting DeviceCodeAuth");
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

        String clientId = config.getProperty("o365.clientId");
        String authority = "https://login.microsoftonline.com/"+config.getProperty("o365.tenantId");

        PublicClientApplication app = PublicClientApplication.builder(clientId)
                .authority(authority)
                .build();

        Set<String> scopes = Collections.singleton("Mail.Send"); // or Graph API scopes

        DeviceCodeFlowParameters parameters = DeviceCodeFlowParameters
                .builder(scopes, deviceCode -> {
                    System.out.println(deviceCode.message());
                })
                .build();

        CompletableFuture<IAuthenticationResult> future = app.acquireToken(parameters);
        IAuthenticationResult result = future.get();

        System.out.println("Access Token: " + result.accessToken());
    }
}
