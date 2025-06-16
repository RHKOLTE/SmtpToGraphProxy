package com.ksh.subethamail.util;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.*;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.text.SimpleDateFormat;

public class MimeMessageLogger {
	
	private final static Logger log = LoggerFactory.getLogger(MimeMessageLogger.class);

	private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    /**
     * Logs all details of a MimeMessage including headers, content, and attachments
     * @param message The MimeMessage to log
     */
    public static void logMimeMessage(MimeMessage message) {
        try {
             log.info("=== MIME MESSAGE DETAILS ===");
           
            // Basic message information
            logBasicInfo(message);
            
            // Headers
            logHeaders(message);
            
            // Content analysis
            logContent(message, 0);
            
             log.info("=== END MESSAGE DETAILS ===\n");
            
        } catch (Exception ex) {
        	log.error("Error logging MimeMessage:: {}", ex.toString(), ex);  // Logs stack trace
            ex.printStackTrace();
        }
    }
    
    /**
     * Logs basic message information
     */
    private static void logBasicInfo(MimeMessage message) throws MessagingException {
         log.info("\n--- BASIC INFORMATION ---");
        
        // Subject
        String subject = message.getSubject();
         log.info("Subject: " + (subject != null ? subject : "[No Subject]"));
        
        // From
        Address[] from = message.getFrom();
         log.info("From: " + formatAddresses(from));
        
        // To
        Address[] to = message.getRecipients(Message.RecipientType.TO);
         log.info("To: " + formatAddresses(to));
        
        // CC
        Address[] cc = message.getRecipients(Message.RecipientType.CC);
        if (cc != null && cc.length > 0) {
             log.info("CC: " + formatAddresses(cc));
        }
        
        // BCC
        Address[] bcc = message.getRecipients(Message.RecipientType.BCC);
        if (bcc != null && bcc.length > 0) {
             log.info("BCC: " + formatAddresses(bcc));
        }
        
        // Reply-To
        Address[] replyTo = message.getReplyTo();
        if (replyTo != null && replyTo.length > 0) {
             log.info("Reply-To: " + formatAddresses(replyTo));
        }
        
        // Date
        Date sentDate = message.getSentDate();
        if (sentDate != null) {
             log.info("Sent Date: " + DATE_FORMAT.format(sentDate));
        }
        
        Date receivedDate = message.getReceivedDate();
        if (receivedDate != null) {
             log.info("Received Date: " + DATE_FORMAT.format(receivedDate));
        }
        
        // Message ID
        String messageId = message.getMessageID();
        if (messageId != null) {
             log.info("Message ID: " + messageId);
        }
        
        // Size
        try {
            int size = message.getSize();
            if (size > 0) {
                 log.info("Size: " + formatSize(size));
            }
        } catch (MessagingException e) {
            // Size not available
        }
        
        // Content Type
         log.info("Content Type: " + message.getContentType());
    }
    
    /**
     * Logs all message headers
     */
    private static void logHeaders(MimeMessage message) throws MessagingException {
         log.info("\n--- ALL HEADERS ---");
        
        Enumeration<Header> headers = message.getAllHeaders();
        while (headers.hasMoreElements()) {
            Header header = headers.nextElement();
             log.info(header.getName() + ": " + header.getValue());
        }
    }
    
    /**
     * Recursively logs message content including multipart and attachments
     */
    private static void logContent(Part part, int level) throws MessagingException, IOException {
        String indent = createIndent(level);
        
         log.info("\n" + indent + "--- CONTENT PART (Level " + level + ") ---");
         log.info(indent + "Content Type: " + part.getContentType());
         log.info(indent + "Disposition: " + part.getDisposition());
         log.info(indent + "Size: " + formatSize(part.getSize()));
        
        // Check if it's an attachment
        String disposition = part.getDisposition();
        String fileName = part.getFileName();
        
        if (fileName != null) {
             log.info(indent + "Filename: " + fileName);
        }
        
        boolean isAttachment = Part.ATTACHMENT.equalsIgnoreCase(disposition) || 
                              Part.INLINE.equalsIgnoreCase(disposition) ||
                              fileName != null;
        
        if (isAttachment) {
             log.info(indent + "*** ATTACHMENT DETECTED ***");
            logAttachment(part, level);
        }
        
        // Handle different content types
        try {
            if (part.isMimeType("text/plain")) {
                 log.info(indent + "--- TEXT CONTENT ---");
                String content = (String) part.getContent();
                 log.info(indent + "Text Length: " + (content != null ? content.length() : 0));
                if (content != null && !isAttachment) {
                    // Show first 200 characters of text content
                    String preview = content.length() > 200 ? 
                        content.substring(0, 200) + "..." : content;
                     log.info(indent + "Preview: " + preview.replace("\n", "\\n"));
                }
                
            } else if (part.isMimeType("text/html")) {
                 log.info(indent + "--- HTML CONTENT ---");
                String content = (String) part.getContent();
                 log.info(indent + "HTML Length: " + (content != null ? content.length() : 0));
                if (content != null && !isAttachment) {
                    // Show first 200 characters of HTML content
                    String preview = content.length() > 200 ? 
                        content.substring(0, 200) + "..." : content;
                     log.info(indent + "Preview: " + preview.replace("\n", "\\n"));
                }
                
            } else if (part.isMimeType("multipart/*")) {
                 log.info(indent + "--- MULTIPART CONTENT ---");
                Multipart multipart = (Multipart) part.getContent();
                int count = multipart.getCount();
                 log.info(indent + "Number of parts: " + count);
                
                for (int i = 0; i < count; i++) {
                     log.info(indent + "Processing part " + (i + 1) + " of " + count);
                    logContent(multipart.getBodyPart(i), level + 1);
                }
                
            } else {
                 log.info(indent + "--- BINARY/OTHER CONTENT ---");
                 log.info(indent + "Content class: " + 
                    (part.getContent() != null ? part.getContent().getClass().getName() : "null"));
            }
            
        } catch (Exception ex) {
        	log.error("Error reading content: {}", ex.toString(), ex);  // Logs stack trace
        }
    }
    
    /**
     * Logs attachment-specific details
     */
    private static void logAttachment(Part part, int level) throws MessagingException, IOException {
        String indent = createIndent(level);
        
         log.info(indent + "Attachment Details:");
         log.info(indent + "  Filename: " + part.getFileName());
         log.info(indent + "  Content-Type: " + part.getContentType());
         log.info(indent + "  Size: " + formatSize(part.getSize()));
         log.info(indent + "  Disposition: " + part.getDisposition());
        
        // Additional headers for attachments
        if (part instanceof MimePart) {
            MimePart mimePart = (MimePart) part;
            try {
                String contentId = mimePart.getContentID();
                if (contentId != null) {
                     log.info(indent + "  Content-ID: " + contentId);
                }
            } catch (MessagingException e) {
                // Content-ID not available
            }
        }
        
        // Try to get input stream info
        try {
            InputStream is = part.getInputStream();
            if (is != null) {
                 log.info(indent + "  Input stream available: Yes");
                is.close();
            }
        } catch (Exception ex) {
        	log.error("Input stream error: {}", ex.toString(), ex);  // Logs stack trace
        }
    }
    
    /**
     * Formats email addresses for display
     */
    private static String formatAddresses(Address[] addresses) {
        if (addresses == null || addresses.length == 0) {
            return "[None]";
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < addresses.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(addresses[i].toString());
        }
        return sb.toString();
    }
    
    /**
     * Creates indentation string for the given level (JDK 8 compatible)
     */
    private static String createIndent(int level) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
        return sb.toString();
    }
    
    /**
     * Formats file size in human-readable format
     */
    private static String formatSize(int size) {
        if (size < 0) return "Unknown";
        if (size < 1024) return size + " bytes";
        if (size < 1024 * 1024) return String.format("%.1f KB", size / 1024.0);
        return String.format("%.1f MB", size / (1024.0 * 1024.0));
    }

}