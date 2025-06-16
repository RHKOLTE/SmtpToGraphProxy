# SmtpToGraphProxy
This is SMTP server is based on SubEtha SMTP is a Java library for receiving SMTP mail and sending them to Microsoft 365 modern authentication server.
Manually download the jar microsoft-graph-6.41.0.jar and keep it in the lib folder.
https://mvnrepository.com/artifact/com.microsoft.graph/microsoft-graph/6.41.0

How to test.
Use Send-MailMessageSMTP.ps1 file with below inputs.
If the SmtpToGraphProxy is running the below powershell script wll conect to the SmtpToGraphProxy and try to send an email.
If the corrosponding to and cc and bcc user must receive the email with attachments.
