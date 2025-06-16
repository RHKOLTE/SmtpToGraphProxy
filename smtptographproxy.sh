#!/bin/bash

# Check if command argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 [start|stop|status]"
    echo "  start  - Start the SMTP to Graph Proxy service"
    echo "  stop   - Stop the SMTP to Graph Proxy service"
    echo "  status - Check if the service is running"
    exit 1
fi

# Set configuration variables - adjust Java path for your Linux system
export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
export OLDPATH="$PATH"
export PATH="$JAVA_HOME/bin:$OLDPATH"

APP_NAME="SmtpToGraphProxy"
SMTPSERVERPORT="2525"
LOG_DIR="logs"
PID_FILE="$LOG_DIR/$APP_NAME.pid"
LOG_FILE="$LOG_DIR/$APP_NAME.log"

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to build classpath
build_classpath() {
    JARS=".:target/classes"
    for jar in lib/*.jar; do
        if [ -f "$jar" ]; then
            JARS="$JARS:$jar"
        fi
    done
}

# Function to get process PID using the specified port
get_process_pid() {
    FOUND_PID=$(lsof -ti tcp:$SMTPSERVERPORT 2>/dev/null)
}

# Function to start service
start_service() {
    echo "[$(date)] Starting $APP_NAME..."
    echo "[$(date)] Starting $APP_NAME..." >> "$LOG_FILE"
    
    # Check if service is already running
    get_process_pid
    if [ ! -z "$FOUND_PID" ]; then
        echo "[ERROR] Service is already running with PID $FOUND_PID"
        echo "[$(date)] [ERROR] Service is already running with PID $FOUND_PID" >> "$LOG_FILE"
        return 1
    fi
    
    # Build classpath
    build_classpath
    
    # Echo the classpath info
    echo "Using classpath:" >> "$LOG_FILE"
    echo "$JARS" >> "$LOG_FILE"
    echo "------------------------------------------------" >> "$LOG_FILE"
    
    # Start the application in background
    echo "Starting Java application..."
    nohup "$JAVA_HOME/bin/java" -Dapp.name=$APP_NAME -classpath "$JARS" com.ksh.subethamail.SmtpToGraphProxy -config config.properties > /dev/null 2>&1 &
    
    # Wait for the application to start
    sleep 10
    
    # Get the PID of the started process
    get_process_pid
    if [ ! -z "$FOUND_PID" ]; then
        echo "$FOUND_PID" > "$PID_FILE"
        echo "[INFO] $APP_NAME started successfully with PID $FOUND_PID"
        echo "[$(date)] [INFO] $APP_NAME started successfully with PID $FOUND_PID" >> "$LOG_FILE"
    else
        echo "[ERROR] Failed to start $APP_NAME or unable to determine PID"
        echo "[$(date)] [ERROR] Failed to start $APP_NAME or unable to determine PID" >> "$LOG_FILE"
        return 1
    fi
}

# Function to stop service
stop_service() {
    echo "[$(date)] Stopping $APP_NAME..."
    echo "[$(date)] Stopping $APP_NAME..." >> "$LOG_FILE"
    
    get_process_pid
    if [ -z "$FOUND_PID" ]; then
        echo "[INFO] No process found running on port $SMTPSERVERPORT"
        echo "[$(date)] [INFO] No process found running on port $SMTPSERVERPORT" >> "$LOG_FILE"
        return 0
    fi
    
    echo "Attempting to kill process with PID $FOUND_PID..."
    kill -TERM "$FOUND_PID" 2>/dev/null
    
    # Wait a few seconds and check if process is still running
    sleep 5
    if kill -0 "$FOUND_PID" 2>/dev/null; then
        # Process still running, force kill
        kill -KILL "$FOUND_PID" 2>/dev/null
    fi
    
    # Check if process was successfully killed
    if ! kill -0 "$FOUND_PID" 2>/dev/null; then
        echo "[INFO] $APP_NAME with PID $FOUND_PID has been stopped successfully"
        echo "[$(date)] [INFO] $APP_NAME with PID $FOUND_PID has been stopped successfully" >> "$LOG_FILE"
        # Remove PID file
        [ -f "$PID_FILE" ] && rm "$PID_FILE"
    else
        echo "[ERROR] Failed to stop process with PID $FOUND_PID"
        echo "[$(date)] [ERROR] Failed to stop process with PID $FOUND_PID" >> "$LOG_FILE"
        return 1
    fi
}

# Function to check service status
status_service() {
    get_process_pid
    if [ ! -z "$FOUND_PID" ]; then
        echo "[INFO] Server is running with PID $FOUND_PID"
    else
        echo "[INFO] Server is not running"
    fi
}

# Convert command to lowercase for case-insensitive comparison
COMMAND=$(echo "$1" | tr '[:upper:]' '[:lower:]')

# Route to appropriate function based on command
case "$COMMAND" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    status)
        status_service
        ;;
    *)
        echo "Invalid command: $1"
        echo "Usage: $0 [start|stop|status]"
        exit 1
        ;;
esac

# Restore PATH
export PATH="$OLDPATH"
