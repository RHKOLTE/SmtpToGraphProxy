#!/bin/bash

# Set Maven and Java paths - adjust these paths for your Linux system
export MAVEN_HOME="/opt/apache-maven-3.9.9"
export M2_HOME="/opt/apache-maven-3.9.9"
export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"

# Update PATH
export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$M2_HOME/bin:$PATH"

# Download dependencies to lib directory
mvn dependency:copy-dependencies -DoutputDirectory=lib
