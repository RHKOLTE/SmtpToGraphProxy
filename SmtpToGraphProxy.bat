@echo off
setlocal enabledelayedexpansion

:: Check if command argument is provided
if "%1"=="" (
    echo Usage: %0 [Start^|Stop^|Status^|GetCode]
    echo   Start   - Start the SMTP to Graph Proxy service
    echo   Stop    - Stop the SMTP to Graph Proxy service
    echo   Status  - Check if the service is running
	echo   GetCode - Run DeviceCodeAuth to perform interactive MFA
    exit /b 1
)

:: Set configuration variables
set "JAVA_HOME=E:\Work\java\sapjvm_8_Win64"
set "OLDPATH=%PATH%"
set "PATH=%JAVA_HOME%\bin;%OLDPATH%"
set "APP_NAME=SmtpToGraphProxy"
set "SMTPSERVERPORT=2525"
set "LOG_DIR=logs"
set "PID_FILE=%LOG_DIR%\%APP_NAME%.pid"
set "LOG_FILE=%LOG_DIR%\%APP_NAME%.log"


:: Create logs directory if it doesn't exist
if not exist %LOG_DIR% mkdir %LOG_DIR%

:: Convert command to uppercase for case-insensitive comparison
set "COMMAND=%1"
for %%i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do call set "COMMAND=%%COMMAND:%%i=%%i%%"

:: Route to appropriate function based on command
if /i "%COMMAND%"=="START" goto :StartService
if /i "%COMMAND%"=="STOP" goto :StopService
if /i "%COMMAND%"=="STATUS" goto :StatusService
if /i "%COMMAND%"=="GETCODE" goto :GetCode

echo Invalid command: %1
echo Usage: %0 [Start^|Stop^|Status]
exit /b 1

:StartService
echo [%date% %time%] Starting %APP_NAME%...
echo [%date% %time%] Starting %APP_NAME%... >> "%LOG_FILE%"

:: Check if service is already running
call :GetProcessPID
if not "!found_pid!"=="" (
    echo [ERROR] Service is already running with PID !found_pid!
    echo [%date% %time%] [ERROR] Service is already running with PID !found_pid! >> "%LOG_FILE%"
    goto :RestorePath
)

:: Build classpath
call :BuildClasspath

:: Echo the classpath info
echo Using classpath: >> "%LOG_FILE%"
echo %JARS% >> "%LOG_FILE%"
echo ------------------------------------------------ >> "%LOG_FILE%"

:: Start the application
echo Starting Java application...
start "%APP_NAME%" /min "%JAVA_HOME%\bin\javaw" -Dapp.name=%APP_NAME% -classpath "%JARS%" com.ksh.subethamail.SmtpToGraphProxy -config config.properties
:: Wait for the application to start
timeout /t 20 >nul

:: Get the PID of the started process
call :GetProcessPID
if not "!found_pid!"=="" (
    echo !found_pid! > "%PID_FILE%"
    echo [INFO] %APP_NAME% started successfully with PID !found_pid!
    echo [%date% %time%] [INFO] %APP_NAME% started successfully with PID !found_pid! >> "%LOG_FILE%"
) else (
    echo [ERROR] Failed to start %APP_NAME% or unable to determine PID
    echo [%date% %time%] [ERROR] Failed to start %APP_NAME% or unable to determine PID >> "%LOG_FILE%"
)
goto :RestorePath

:StopService
echo [%date% %time%] Stopping %APP_NAME%...
echo [%date% %time%] Stopping %APP_NAME%... >> "%LOG_FILE%"

call :GetProcessPID
if "!found_pid!"=="" (
    echo [INFO] No process found running on port %SMTPSERVERPORT%
    echo [%date% %time%] [INFO] No process found running on port %SMTPSERVERPORT% >> "%LOG_FILE%"
    goto :RestorePath
)

echo Attempting to kill process with PID !found_pid!...
taskkill /PID !found_pid! /F >nul 2>&1
if !errorlevel! equ 0 (
    echo [INFO] %APP_NAME% with PID !found_pid! has been stopped successfully
    echo [%date% %time%] [INFO] %APP_NAME% with PID !found_pid! has been stopped successfully >> "%LOG_FILE%"
    :: Remove PID file
    if exist "%PID_FILE%" del "%PID_FILE%"
) else (
    echo [ERROR] Failed to stop process with PID !found_pid!
    echo [%date% %time%] [ERROR] Failed to stop process with PID !found_pid! >> "%LOG_FILE%"
)
goto :RestorePath

:StatusService
call :GetProcessPID
if not "!found_pid!"=="" (
    echo [INFO] Server is running with PID !found_pid!
) else (
    echo [INFO] Server is not running
)
goto :RestorePath

:GetCode
 echo Running DeviceCodeAuth to retrieve device login code...
:: Build classpath
call :BuildClasspath

:: Echo the classpath info
echo Using classpath: >> "%LOG_FILE%"
echo %JARS% >> "%LOG_FILE%"
echo ------------------------------------------------ >> "%LOG_FILE%"

:: Start the application
echo Starting Java application...
"%JAVA_HOME%\bin\java" -Dapp.name=%APP_NAME% -classpath "%JARS%" com.ksh.subethamail.util.DeviceCodeAuth -config config.properties
:: Wait for the application to start
timeout /t 10 >nul
goto :RestorePath

:GetProcessPID
set "found_pid="
:: Use netstat to find the process using the specified port
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":%SMTPSERVERPORT% "') do (
    set "found_pid=%%a"
    goto :EndGetPID
)
:EndGetPID
exit /b

:BuildClasspath
set "JARS=.;target\classes"
for %%f in (lib\*.jar) do (
    call :add_jar "%%f"
)
exit /b

:add_jar
set "JARS=%JARS%;%~1"
exit /b

:RestorePath
set "PATH=%OLDPATH%"
exit /b