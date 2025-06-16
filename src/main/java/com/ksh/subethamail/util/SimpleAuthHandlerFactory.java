package com.ksh.subethamail.util;

import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.subethamail.smtp.AuthenticationHandler;
import org.subethamail.smtp.AuthenticationHandlerFactory;
import org.subethamail.smtp.RejectException;
import org.subethamail.smtp.util.Base64;
import org.subethamail.smtp.util.TextUtils;

public class SimpleAuthHandlerFactory implements AuthenticationHandlerFactory {
	private final static Logger log = LoggerFactory.getLogger(SimpleAuthHandlerFactory.class);
	private final String validUsername;
	private final String validPassword;

	public SimpleAuthHandlerFactory(String username, String password) {
		this.validUsername = username;
		this.validPassword = password;
		log.debug("SimpleAuthHandlerFactory init done");
	}

	@Override
	public List<String> getAuthenticationMechanisms() {
		return Arrays.asList("LOGIN");
	}

	@Override
	public AuthenticationHandler create() {
		return new AuthenticationHandler() {
			private String username;
			private String password;

			@Override
			public String auth(String clientInput) throws RejectException {
				log.debug("SimpleAuthHandlerFactory data received=" + clientInput);
				StringTokenizer stk = new StringTokenizer(clientInput);
				String token = stk.nextToken();
				if (token.trim().equalsIgnoreCase("AUTH")) {
					if (!stk.nextToken().trim().equalsIgnoreCase("LOGIN")) {
						// Mechanism mismatch
						throw new RejectException(504, "AUTH mechanism mismatch");
					}

					if (stk.hasMoreTokens()) {
						// The client submitted an initial response, which should be
						// the username.
						// .Net's built in System.Net.Mail.SmtpClient sends its
						// authentication this way (and this way only).
						byte[] decoded = Base64.decode(stk.nextToken());
						if (decoded == null)
							throw new RejectException(501, /* 5.5.4 */
									"Invalid command argument, not a valid Base64 string");
						this.username = TextUtils.getStringUtf8(decoded);

						return "334 " + Base64.encodeToString(TextUtils.getAsciiBytes("Password:"), false);
					} else {
						return "334 " + Base64.encodeToString(TextUtils.getAsciiBytes("Username:"), false);
					}
				}

				if (this.username == null) {
					byte[] decoded = Base64.decode(clientInput);
					if (decoded == null) {
						throw new RejectException(501, /* 5.5.4 */
								"Invalid command argument, not a valid Base64 string");
					}

					this.username = TextUtils.getStringUtf8(decoded);

					return "334 " + Base64.encodeToString(TextUtils.getAsciiBytes("Password:"), false);
				}

				byte[] decoded = Base64.decode(clientInput);
				if (decoded == null) {
					throw new RejectException(501, /* 5.5.4 */
							"Invalid command argument, not a valid Base64 string");
				}

				this.password = TextUtils.getStringUtf8(decoded);
				if (username.equals(validUsername) && password.equals(validPassword)) {
					return null; // success
				} else {
					throw new RuntimeException("Authentication failed");
				}
			}

			@Override
			public Object getIdentity() {
				return username;
			}
		};
	}
}
