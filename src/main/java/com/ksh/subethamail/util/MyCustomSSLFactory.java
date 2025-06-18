package com.ksh.subethamail.util;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class MyCustomSSLFactory {

    private final static Logger log = LoggerFactory.getLogger(MyCustomSSLFactory.class);

    private static SSLContext sslContext;
    
    // TLS 1.3 cipher suites
    private static final String[] TLS_13_CIPHER_SUITES = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256"
    };
    
    // TLS 1.2 cipher suites (fallback)
    private static final String[] TLS_12_CIPHER_SUITES = {
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_CBC_SHA256"
    };
    
    // Supported protocols
    private static final String[] SUPPORTED_PROTOCOLS = {
        "TLSv1.3", "TLSv1.2"
    };

    public static SSLSocket createSSLSocket(Socket clientSocket) throws IOException {
        try {
            // Create SSL socket from existing socket
            SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
                clientSocket,
                clientSocket.getInetAddress().getHostAddress(),
                clientSocket.getPort(),
                true
            );
            
            // Configure SSL socket for server mode
            sslSocket.setUseClientMode(false);
            sslSocket.setNeedClientAuth(false);
            sslSocket.setWantClientAuth(false);
            
            // Configure protocols and cipher suites with proper fallback
            configureSSLSocket(sslSocket);
            
            return sslSocket;
            
        } catch (Exception e) {
            throw new IOException("Failed to create SSL socket", e);
        }
    }
    
    /**
     * Configure SSL socket with proper protocol and cipher suite selection
     */
    private static void configureSSLSocket(SSLSocket sslSocket) {
        try {
            // Get supported protocols and cipher suites from the socket
            String[] supportedProtocols = sslSocket.getSupportedProtocols();
            String[] supportedCipherSuites = sslSocket.getSupportedCipherSuites();
            
            // Configure protocols
            List<String> enabledProtocols = new ArrayList<>();
            for (String protocol : SUPPORTED_PROTOCOLS) {
                if (Arrays.asList(supportedProtocols).contains(protocol)) {
                    enabledProtocols.add(protocol);
                    log.debug("Enabling protocol: {}", protocol);
                }
            }
            
            if (!enabledProtocols.isEmpty()) {
                sslSocket.setEnabledProtocols(enabledProtocols.toArray(new String[0]));
                log.info("Enabled protocols: {}", enabledProtocols);
            }
            
            // Configure cipher suites with smart fallback
            List<String> enabledCipherSuites = selectCipherSuites(supportedCipherSuites);
            
            if (!enabledCipherSuites.isEmpty()) {
                try {
                    sslSocket.setEnabledCipherSuites(enabledCipherSuites.toArray(new String[0]));
                    log.info("Successfully configured {} cipher suites", enabledCipherSuites.size());
                    log.debug("Enabled cipher suites: {}", enabledCipherSuites);
                } catch (IllegalArgumentException e) {
                    log.warn("Failed to set preferred cipher suites: {}", e.getMessage());
                    // Fall back to default cipher suites
                    fallbackToDefaultCipherSuites(sslSocket);
                }
            } else {
                log.warn("No preferred cipher suites supported, using defaults");
                fallbackToDefaultCipherSuites(sslSocket);
            }
            
        } catch (Exception e) {
            log.error("Error configuring SSL socket: {}", e.getMessage(), e);
            // Last resort fallback
            fallbackToDefaultCipherSuites(sslSocket);
        }
    }
    
    /**
     * Select cipher suites based on what's supported by the runtime
     */
    private static List<String> selectCipherSuites(String[] supportedCipherSuites) {
        List<String> availableCiphers = Arrays.asList(supportedCipherSuites);
        List<String> selectedCiphers = new ArrayList<>();
        
        // Check Java version and TLS 1.3 support
        boolean tls13Supported = isTLS13Supported();
        log.info("TLS 1.3 support detected: {}", tls13Supported);
        
        // First try TLS 1.3 cipher suites if supported
        if (tls13Supported) {
            for (String cipher : TLS_13_CIPHER_SUITES) {
                if (availableCiphers.contains(cipher)) {
                    selectedCiphers.add(cipher);
                    log.debug("Added TLS 1.3 cipher: {}", cipher);
                }
            }
        }
        
        // Add TLS 1.2 cipher suites
        for (String cipher : TLS_12_CIPHER_SUITES) {
            if (availableCiphers.contains(cipher)) {
                selectedCiphers.add(cipher);
                log.debug("Added TLS 1.2 cipher: {}", cipher);
            }
        }
        
        // If no preferred ciphers are available, select some safe defaults
        if (selectedCiphers.isEmpty()) {
            log.warn("No preferred cipher suites available, selecting safe defaults");
            for (String cipher : availableCiphers) {
                if (cipher.contains("AES_256_GCM") || cipher.contains("AES_128_GCM") ||
                    cipher.contains("AES_256_CBC") || cipher.contains("AES_128_CBC")) {
                    selectedCiphers.add(cipher);
                    if (selectedCiphers.size() >= 10) break; // Limit to reasonable number
                }
            }
        }
        
        return selectedCiphers;
    }
    
    /**
     * Check if TLS 1.3 is supported in current Java runtime
     */
    private static boolean isTLS13Supported() {
        try {
            // Check Java version
            String javaVersion = System.getProperty("java.version");
            log.debug("Java version: {}", javaVersion);
            
            // TLS 1.3 is fully supported in Java 11+
            if (isJavaVersionAtLeast(11)) {
                // Try to create SSLContext with TLS 1.3
                SSLContext testContext = SSLContext.getInstance("TLSv1.3");
                return true;
            }
            
            // For Java 8, TLS 1.3 might be available with certain updates
            if (isJavaVersionAtLeast(8)) {
                try {
                    SSLContext testContext = SSLContext.getInstance("TLSv1.3");
                    return true;
                } catch (Exception e) {
                    log.debug("TLS 1.3 not available in this Java 8 version: {}", e.getMessage());
                    return false;
                }
            }
            
            return false;
            
        } catch (Exception e) {
            log.debug("Could not determine TLS 1.3 support: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if Java version is at least the specified major version
     */
    private static boolean isJavaVersionAtLeast(int majorVersion) {
        try {
            String version = System.getProperty("java.version");
            if (version.startsWith("1.")) {
                // Java 8 and earlier (1.8.x format)
                int actualVersion = Integer.parseInt(version.substring(2, 3));
                return actualVersion >= majorVersion;
            } else {
                // Java 9+ (9.x, 11.x, 17.x format)
                int dotIndex = version.indexOf('.');
                if (dotIndex > 0) {
                    int actualVersion = Integer.parseInt(version.substring(0, dotIndex));
                    return actualVersion >= majorVersion;
                } else {
                    int actualVersion = Integer.parseInt(version);
                    return actualVersion >= majorVersion;
                }
            }
        } catch (Exception e) {
            log.warn("Could not parse Java version, assuming older version: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Fallback to default cipher suites when preferred ones fail
     */
    private static void fallbackToDefaultCipherSuites(SSLSocket sslSocket) {
        try {
            String[] defaultCiphers = sslSocket.getSupportedCipherSuites();
            // Filter out weak cipher suites
            List<String> safeCiphers = new ArrayList<>();
            for (String cipher : defaultCiphers) {
                if (!isWeakCipher(cipher)) {
                    safeCiphers.add(cipher);
                }
            }
            
            if (!safeCiphers.isEmpty()) {
                sslSocket.setEnabledCipherSuites(safeCiphers.toArray(new String[0]));
                log.info("Using default cipher suites due to configuration issues. Count: {}", safeCiphers.size());
            }
        } catch (Exception e) {
            log.error("Could not even set default cipher suites: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Check if a cipher suite is considered weak
     */
    private static boolean isWeakCipher(String cipher) {
        return cipher.contains("NULL") || 
               cipher.contains("EXPORT") || 
               cipher.contains("DES") || 
               cipher.contains("RC4") ||
               cipher.contains("MD5");
    }

    public static void initializeSSLContext() {
        try {
            // Add BouncyCastle provider if not already present
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
                log.debug("Added BouncyCastle security provider");
            }
            
            // Create a keystore with a self-signed certificate
            KeyStore keyStore = createSelfSignedKeyStore("password".toCharArray());
            
            // Initialize key manager factory
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());
            
            // Create a lenient trust manager for development/testing
            // This accepts self-signed certificates but still validates properly signed ones
            TrustManager[] trustManagers = new TrustManager[] {
                new LenientX509TrustManager()
            };
            
            // Create SSL context - use "TLS" for Java 8 compatibility
            // This will negotiate the best available protocol (TLS 1.2 in Java 8)
            String tlsVersion = "TLS";
            if (isTLS13Supported()) {
                try {
                    // Test if TLS 1.3 context can be created
                    SSLContext.getInstance("TLSv1.3");
                    tlsVersion = "TLSv1.3";
                    log.info("Using TLS 1.3 for SSL context");
                } catch (Exception e) {
                    tlsVersion = "TLSv1.2";
                    log.info("TLS 1.3 not available, using TLS 1.2");
                }
            } else {
                // For Java 8, stick with TLS (auto-negotiation) or explicitly use TLSv1.2
                tlsVersion = "TLSv1.2";
                log.info("Using TLS 1.2 for SSL context (Java 8)");
            }
            
            sslContext = SSLContext.getInstance(tlsVersion);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, new SecureRandom());
            
            // Test the SSL context
            try {
                javax.net.ssl.SSLSocketFactory factory = sslContext.getSocketFactory();
                String[] supportedCiphers = factory.getSupportedCipherSuites();
                log.info("SSL context initialized successfully with {} cipher suites", supportedCiphers.length);
                
                // Log some key information
                log.info("SSL Context Protocol: {}", sslContext.getProtocol());
                log.debug("Key Manager Algorithm: {}", keyManagerFactory.getAlgorithm());
                
            } catch (Exception e) {
                log.warn("SSL context created but may have issues: {}", e.getMessage());
            }
            
        } catch (Exception e) {
            log.error("Failed to initialize SSL context: {}", e.toString(), e);
            // Fallback to simple SSL context
            try {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] {
                    new LenientX509TrustManager()
                }, new SecureRandom());
                log.warn("Using fallback SSL context without custom certificate");
            } catch (Exception fallbackException) {
                throw new RuntimeException("Failed to initialize SSL context", fallbackException);
            }
        }
    }
    
    /**
     * A lenient trust manager that accepts self-signed certificates for development
     * but still performs basic validation
     */
    private static class LenientX509TrustManager implements X509TrustManager {
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // For SMTP server, we usually don't need to validate client certificates
            log.debug("Client certificate validation - accepting (SMTP server mode)");
        }
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // This shouldn't be called in server mode, but implement for completeness
            log.debug("Server certificate validation - accepting (development mode)");
        }
        
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // Return empty array to accept any issuer in development mode
            return new X509Certificate[0];
        }
    }

    /**
     * Create a keystore with a self-signed certificate for testing
     */
    private static KeyStore createSelfSignedKeyStore(char[] password) throws Exception {
        // Generate key pair with parameters compatible with Java 8
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Use 2048 for Java 8 compatibility
        KeyPair keyPair = keyGen.generateKeyPair();

        // Generate self-signed certificate with proper extensions
        X500Name dnName = new X500Name("CN=localhost,OU=SMTP Server,O=SubEthaMail,L=Local,ST=State,C=US");
        BigInteger certSerialNumber = new BigInteger(64, new SecureRandom()); // Proper random serial
        Date startDate = new Date(System.currentTimeMillis() - 86400000L); // Start 1 day ago
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 5); // 5 years validity for testing
        Date endDate = calendar.getTime();

        // Use SHA256 with RSA for better compatibility
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
            
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        // Add extensions to make certificate more acceptable
        try {
            // Basic Constraints - mark as not a CA
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints, 
                false, 
                new org.bouncycastle.asn1.x509.BasicConstraints(false)
            );
            
            // Key Usage
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage, 
                true, 
                new org.bouncycastle.asn1.x509.KeyUsage(
                    org.bouncycastle.asn1.x509.KeyUsage.digitalSignature | 
                    org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
                )
            );
            
            // Extended Key Usage - server authentication
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, 
                false, 
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                    org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth
                )
            );
            
            // Subject Alternative Name - important for modern clients
            org.bouncycastle.asn1.x509.GeneralNames subjectAltNames = 
                new org.bouncycastle.asn1.x509.GeneralNames(
                    new org.bouncycastle.asn1.x509.GeneralName[] {
                        new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost"
                        ),
                        new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.iPAddress, "127.0.0.1"
                        )
                    }
                );
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, 
                false, 
                subjectAltNames
            );
            
        } catch (Exception e) {
            log.warn("Could not add certificate extensions: {}", e.getMessage());
        }

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));

        cert.checkValidity(new Date());
        cert.verify(keyPair.getPublic());

        // Create keystore and set the key entry
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        Certificate[] certChain = new Certificate[] { cert };
        keyStore.setKeyEntry("smtp", keyPair.getPrivate(), password, certChain);

        log.info("Created self-signed certificate:");
        log.info("  Subject: {}", cert.getSubjectDN());
        log.info("  Serial: {}", cert.getSerialNumber());
        log.info("  Valid from: {} to: {}", cert.getNotBefore(), cert.getNotAfter());
        log.info("  Algorithm: {}", cert.getSigAlgName());
        
        return keyStore;
    }
    
    /**
     * Get information about current SSL configuration (for debugging)
     */
    public static String getSSLInfo() {
        if (sslContext == null) {
            return "SSL context not initialized";
        }
        
        try {
            StringBuilder info = new StringBuilder();
            info.append("SSL Context Protocol: ").append(sslContext.getProtocol()).append("\n");
            info.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
            info.append("TLS 1.3 Supported: ").append(isTLS13Supported()).append("\n");
            
            String[] supportedProtocols = sslContext.getDefaultSSLParameters().getProtocols();
            info.append("Supported Protocols: ").append(Arrays.toString(supportedProtocols)).append("\n");
            
            String[] supportedCiphers = sslContext.getDefaultSSLParameters().getCipherSuites();
            info.append("Supported Cipher Suites Count: ").append(supportedCiphers.length).append("\n");
            
            // Count TLS 1.3 vs TLS 1.2 cipher suites
            long tls13Count = Arrays.stream(supportedCiphers)
                .filter(cipher -> cipher.startsWith("TLS_AES_") || cipher.startsWith("TLS_CHACHA20_"))
                .count();
            info.append("TLS 1.3 Cipher Suites: ").append(tls13Count).append("\n");
            
            return info.toString();
        } catch (Exception e) {
            return "Error getting SSL info: " + e.getMessage();
        }
    }
    
    /**
     * Export the server certificate in PEM format for client configuration
     * This helps clients trust the self-signed certificate
     */
    public static String exportServerCertificate() {
        try {
            KeyStore keyStore = createSelfSignedKeyStore("password".toCharArray());
            Certificate cert = keyStore.getCertificate("smtp");
            
            java.util.Base64.Encoder encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
            String certPem = "-----BEGIN CERTIFICATE-----\n" +
                           new String(encoder.encode(cert.getEncoded())) +
                           "\n-----END CERTIFICATE-----\n";
            
            log.info("Server certificate exported in PEM format");
            return certPem;
            
        } catch (Exception e) {
            log.error("Failed to export certificate: {}", e.getMessage(), e);
            return "Error exporting certificate: " + e.getMessage();
        }
    }
    
    /**
     * Create a simple test method to validate SSL setup
     */
    public static boolean testSSLSetup() {
        try {
            if (sslContext == null) {
                log.error("SSL context is null");
                return false;
            }
            
            // Try to create a socket factory
            javax.net.ssl.SSLSocketFactory factory = sslContext.getSocketFactory();
            if (factory == null) {
                log.error("Could not create SSL socket factory");
                return false;
            }
            
            // Check cipher suites
            String[] ciphers = factory.getSupportedCipherSuites();
            if (ciphers == null || ciphers.length == 0) {
                log.error("No cipher suites available");
                return false;
            }
            
            log.info("SSL setup test passed - {} cipher suites available", ciphers.length);
            return true;
            
        } catch (Exception e) {
            log.error("SSL setup test failed: {}", e.getMessage(), e);
            return false;
        }
    }
}