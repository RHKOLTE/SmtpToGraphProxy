package com.ksh.subethamail.util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.mail.BodyPart;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimeMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.UsernamePasswordCredential;
import com.azure.identity.UsernamePasswordCredentialBuilder;
import com.microsoft.graph.models.Attachment;
import com.microsoft.graph.models.BodyType;
import com.microsoft.graph.models.EmailAddress;
import com.microsoft.graph.models.FileAttachment;
import com.microsoft.graph.models.ItemBody;
import com.microsoft.graph.models.Message;
import com.microsoft.graph.models.Recipient;
import com.microsoft.graph.serviceclient.GraphServiceClient;
import com.microsoft.graph.users.item.sendmail.SendMailPostRequestBody;

@SuppressWarnings("deprecation")
public class GraphEmailSender {

	private final static Logger log = LoggerFactory.getLogger(GraphEmailSender.class);

	private static GraphServiceClient graphClient;
	private static String LCredentialType;
	final static String[] scopes = new String[] { "https://graph.microsoft.com/.default" };
	private static boolean  BSaveToSentItems = false;
	public static void init(String clientId, String clientSec, String tenantId, String username, String password,
			String CredentialType, String SaveToSentItems) {
		LCredentialType = CredentialType;
		BSaveToSentItems = Boolean.parseBoolean(SaveToSentItems);
		if (CredentialType.equalsIgnoreCase("ClientSecretCredential")) {
			ClientSecretCredential credential = new ClientSecretCredentialBuilder().clientId(clientId)
					.tenantId(tenantId).clientSecret(clientSec).build();
			graphClient = new GraphServiceClient(credential, scopes);
			log.info("GraphServiceClient init done ClientSecretCredential");
		} else if ("UsernamePasswordCredential".equalsIgnoreCase(CredentialType)) {
			UsernamePasswordCredential credential = new UsernamePasswordCredentialBuilder().clientId(clientId)
					.tenantId(tenantId).username(username).password(password).build();
			// Create Graph client with the correct SDK v6+ constructor
			graphClient = new GraphServiceClient(credential, scopes);
			log.info("GraphServiceClient init done UsernamePasswordCredential");
		}
	}

	public static void sendEmail(String from, List<String> envelopeRecipients, MimeMessage mimeMessage)
			throws Exception {
		log.info("GraphServiceClient trying to sendEmail");
		Message graphMessage = new Message();

		// Set subject
		graphMessage.setSubject(mimeMessage.getSubject());

		// Prepare body (text or HTML)
		String bodyContent = extractBody(mimeMessage);
		boolean isHtml = isHtml(mimeMessage);

		ItemBody body = new ItemBody();
		body.setContentType(isHtml ? BodyType.Html : BodyType.Text);
		body.setContent(bodyContent);
		graphMessage.setBody(body);

		// Recipients
		// Recipients: To, CC, BCC
		graphMessage.setToRecipients(convertAddresses(mimeMessage.getRecipients(javax.mail.Message.RecipientType.TO)));
		graphMessage.setCcRecipients(convertAddresses(mimeMessage.getRecipients(javax.mail.Message.RecipientType.CC)));

		// Collect all "To" and "Cc" addresses to exclude from Bcc
		List<Recipient> toRecipients = convertAddresses(mimeMessage.getRecipients(javax.mail.Message.RecipientType.TO));
		List<Recipient> ccRecipients = convertAddresses(mimeMessage.getRecipients(javax.mail.Message.RecipientType.CC));
		log.debug("GraphServiceClient BCC list"
				+ getBccRecipients(toRecipients, ccRecipients, envelopeRecipients).toString());
		graphMessage.setBccRecipients(getBccRecipients(toRecipients, ccRecipients, envelopeRecipients));

		// Attachments
		List<Attachment> attachments = extractAttachments(mimeMessage);
		if (!attachments.isEmpty()) {
			graphMessage.setAttachments(attachments);
		}
		// Create send mail parameter set
		SendMailPostRequestBody sendMailBody = new SendMailPostRequestBody();
		sendMailBody.setMessage(graphMessage);
		sendMailBody.setSaveToSentItems(BSaveToSentItems);

		log.debug("GraphServiceClient trying to send message sendMailBody " + sendMailBody.toString());
		// Send message using the correct API
		try {
			if (LCredentialType.equalsIgnoreCase("ClientSecretCredential")) {
				graphClient.users().byUserId(from).sendMail().post(sendMailBody);
			} else {
				graphClient.me().sendMail().post(sendMailBody);
			}
		} catch (Exception ex) {
			// Optional: log here
			log.info("Error sending email: {}", ex.toString(), ex); // Logs stack trace
			throw ex; // rethrow
		}

		log.info("GraphServiceClient sendEmail done");
	}

	private static String extractBody(MimeMessage message) throws Exception {
		if (message.isMimeType("text/plain") || message.isMimeType("text/html")) {
			return message.getContent().toString();
		} else if (message.isMimeType("multipart/*")) {
			Multipart mp = (Multipart) message.getContent();
			for (int i = 0; i < mp.getCount(); i++) {
				BodyPart part = mp.getBodyPart(i);
				if (part.isMimeType("text/html")) {
					return part.getContent().toString();
				}
				if (part.isMimeType("text/plain")) {
					return part.getContent().toString();
				}
			}
		}
		return "[Unsupported content]";
	}

	private static boolean isHtml(MimeMessage message) throws Exception {
		if (message.isMimeType("text/html"))
			return true;
		if (message.isMimeType("multipart/*")) {
			Multipart mp = (Multipart) message.getContent();
			for (int i = 0; i < mp.getCount(); i++) {
				if (mp.getBodyPart(i).isMimeType("text/html"))
					return true;
			}
		}
		return false;
	}

	private static List<Recipient> convertAddresses(javax.mail.Address[] addresses) {
		if (addresses == null)
			return new ArrayList<>();
		return Arrays.stream(addresses).map(addr -> {
			Recipient recipient = new Recipient();
			EmailAddress email = new EmailAddress();
			email.setAddress(addr.toString());
			recipient.setEmailAddress(email);
			return recipient;
		}).collect(Collectors.toList());
	}

	public static List<String> extractEmailAddresses(List<Recipient> recipients) {
		List<String> emailList = new ArrayList<String>();
		for (int i = 0; i < recipients.size(); i++) {
			Recipient r = recipients.get(i);
			if (r != null && r.getEmailAddress() != null && r.getEmailAddress().getAddress() != null) {
				emailList.add(r.getEmailAddress().getAddress());
			}
		}
		return emailList;
	}

	public static List<Recipient> getBccRecipients(List<Recipient> toRecipients, List<Recipient> ccRecipients,
			List<String> envelopeRecipients) {
		Set<String> toCcEmails = new HashSet<String>();

		// Collect TO email addresses
		for (int i = 0; i < toRecipients.size(); i++) {
			Recipient r = toRecipients.get(i);
			if (r != null && r.getEmailAddress() != null && r.getEmailAddress().getAddress() != null) {
				toCcEmails.add(r.getEmailAddress().getAddress().toLowerCase());
			}
		}

		// Collect CC email addresses
		for (int i = 0; i < ccRecipients.size(); i++) {
			Recipient r = ccRecipients.get(i);
			if (r != null && r.getEmailAddress() != null && r.getEmailAddress().getAddress() != null) {
				toCcEmails.add(r.getEmailAddress().getAddress().toLowerCase());
			}
		}

		// Identify BCC email addresses
		List<String> bccEmails = new ArrayList<String>();
		for (int i = 0; i < envelopeRecipients.size(); i++) {
			String email = envelopeRecipients.get(i);
			if (email != null && !toCcEmails.contains(email.toLowerCase())) {
				bccEmails.add(email);
			}
		}

		// Create Recipient objects for BCC
		List<Recipient> bccRecipients = new ArrayList<Recipient>();
		for (int i = 0; i < bccEmails.size(); i++) {
			String email = bccEmails.get(i);
			Recipient recipient = new Recipient();
			EmailAddress emailAddr = new EmailAddress();
			emailAddr.setAddress(email);
			recipient.setEmailAddress(emailAddr);
			bccRecipients.add(recipient);
		}

		return bccRecipients;
	}

	private static List<Attachment> extractAttachments(MimeMessage message) throws Exception {
		List<Attachment> graphAttachments = new ArrayList<>();
		if (!message.isMimeType("multipart/*"))
			return graphAttachments;

		Multipart multipart = (Multipart) message.getContent();
		for (int i = 0; i < multipart.getCount(); i++) {
			BodyPart part = multipart.getBodyPart(i);
			if (Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())) {
				InputStream is = part.getInputStream();
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();

				byte[] data = new byte[4096];
				int nRead;
				while ((nRead = is.read(data, 0, data.length)) != -1) {
					buffer.write(data, 0, nRead);
				}

				buffer.flush();
				byte[] bytes = buffer.toByteArray();
				FileAttachment attachment = new FileAttachment();
				attachment.setOdataType("#microsoft.graph.fileAttachment");
				attachment.setName(part.getFileName());
				attachment.setContentBytes(bytes);
				attachment.setContentType(part.getContentType());
				graphAttachments.add(attachment);
			}
		}
		return graphAttachments;
	}
}
