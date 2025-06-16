SET MAVEN_HOME=E:\Work\SVN\TomcatPackage\apache-maven-3.9.9
SET M2_HOME=E:\Work\SVN\TomcatPackage\apache-maven-3.9.9
SET JAVA_HOME=C:\usr\share\GLT\openjdk
SEt PATH=%JAVA_HOME%\bin;%MAVEN_HOME%\bin;%M2_HOME%\bin;%PATH% 
mvn dependency:copy-dependencies -DoutputDirectory=lib