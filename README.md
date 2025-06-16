# SmtpToGraphProxy
This is SMTP server based on SubEtha SMTP is a Java library for receiving SMTP mail and sending them to Microsoft 365 modern authentication server.
Manually download the jar microsoft-graph-6.41.0.jar and keep it in the lib folder.
https://mvnrepository.com/artifact/com.microsoft.graph/microsoft-graph/6.41.0

How to test.
Create a Send-MailMessageSMTP.ps1 file with below inputs.
If the SmtpToGraphProxy is running the below powershell script wll conect to the SmtpToGraphProxy and try to send an email.
If the corrosponding to and cc and bcc user must receive the email with attachments.
\# Skip SSL certificate validation to avoid certificate errors
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

\# Define email parameters
$smtpServer = "localhost"
$smtpPort = 2525
$username = "notification@xyzcorp.com"
$password = "password"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $securePassword)
$attachments = @("C:\test\dummy.pdf", "C:\test\dummy1.pdf")

\# Send the email
Send-MailMessage `
    -From "gl-notification@greenlightcorp.com" `
    -To "user1@xyzcorp.com" `
	  -Cc "user1@gmail.com" `
	  -Bcc "user12@gmail.com" `
    -Subject "Test Email from PowerShell" `
    -Body "This is a test email." `
    -SmtpServer $smtpServer `
    -Port $smtpPort `
	  -Attachments $attachments `
	  -UseSsl `
    -Credential $cred
