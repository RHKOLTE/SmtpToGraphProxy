#!/bin/bash

# Set Java home - adjust path as needed for your Linux system
export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
export OLDPATH="$PATH"
export PATH="$JAVA_HOME/bin:$OLDPATH"

# Initialize classpath
JARS="."

# Function to add jar to classpath
add_jar() {
    JARS="$JARS:$1"
}

# Add all jars from lib directory
for jar in lib/*.jar; do
    if [ -f "$jar" ]; then
        add_jar "$jar"
    fi
done

# Create output directory if it doesn't exist
if [ ! -d "target/classes" ]; then
    mkdir -p target/classes
fi

# Find all Java sources and write to sources.txt
find src/main/java -name "*.java" > sources.txt

# Show classpath
echo "Compiling with classpath: $JARS"

# Compile
"$JAVA_HOME/bin/javac" -classpath "$JARS" -d target/classes @sources.txt

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation complete."
    
    # Copy resources from src/main/resources to target/classes
    if [ -d "src/main/resources" ]; then
        cp -r src/main/resources/* target/classes/ 2>/dev/null
        echo "Copy resources to target/classes."
    fi
else
    echo "Compilation failed."
    export PATH="$OLDPATH"
    exit 1
fi

# Restore PATH
export PATH="$OLDPATH"

# Clean up
rm -f sources.txt
