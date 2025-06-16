package com.ksh.subethamail.util;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

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
            
            // Enable common cipher suites and protocols
            String[] enabledCipherSuites = {
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256"
            };
            
            String[] enabledProtocols = {"TLSv1.2", "TLSv1.3"};
            
            // Set supported cipher suites and protocols
            try {
                sslSocket.setEnabledCipherSuites(enabledCipherSuites);
                sslSocket.setEnabledProtocols(enabledProtocols);
            } catch (IllegalArgumentException e) {
                // Fallback to default supported cipher suites
            	log.warn("Using default cipher suites due to: {}", e.getMessage(), e);
            }
            
            // Start handshake
            return sslSocket;
  	    	
	        
	    } catch (Exception e) {
	        throw new IOException("Failed to create SSL socket", e);
	    }
	}
	public static void initializeSSLContext() {
        try {
            // Create a keystore with a self-signed certificate
            KeyStore keyStore = createSelfSignedKeyStore("password".toCharArray());
            
            // Initialize key manager factory
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());
            
            // Create a simple trust-all trust manager for development
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            // Create SSL context
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustAllCerts, new SecureRandom());
            
            log.info("SSL context initialized for STARTTLS with self-signed certificate");
        } catch (Exception e) {
        	log.error("Failed to initialize SSL context: {}", e.toString(), e);  // Logs stack trace
            // Fallback to simple SSL context
            try {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
                }, new SecureRandom());
                log.info("Using fallback SSL context");
            } catch (Exception fallbackException) {
                throw new RuntimeException("Failed to initialize SSL context", fallbackException);
            }
        }
    }
    /**
     * Create a keystore with a self-signed certificate for testing
     */
    private static KeyStore createSelfSignedKeyStore(char[] password) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Generate self-signed certificate
        X500Name dnName = new X500Name("CN=localhost");
        BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));
        Date startDate = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // 1 year validity
        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certBuilder.build(contentSigner));

        cert.checkValidity(new Date());
        cert.verify(keyPair.getPublic());

        // Create keystore and set the key entry
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        Certificate[] certChain = new Certificate[] { cert };
        keyStore.setKeyEntry("smtp", keyPair.getPrivate(), password, certChain);

        return keyStore;
    }
    
    	
}
