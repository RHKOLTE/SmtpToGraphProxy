set JAVA_HOME=E:\Work\java\sapjvm_8_Win64
set OLDPATH=%PATH%
set PATH=%JAVA_HOME%\bin;%OLDPATH%
set JARS=.
for %%f in (lib\*.jar) do (
call :add_jar %%f
)
:: Optional: Create output directory
if not exist target\classes (
    mkdir target\classes
)

:: Find all Java sources
dir /s /B src\main\java\*.java > sources.txt

:: Show classpath
echo Compiling with classpath: %JARS%

:: Compile
%JAVA_HOME%\bin\javac -classpath "%JARS%" -d target\classes @sources.txt

:: Done
echo Compilation complete.

:: Copy resources from src\main\resources to target\classes
xcopy /E /Y /I src\main\resources\* target\classes\

echo Copy resources to to target\classes.
set PATH=%OLDPATH%

exit /b

:add_jar
set JARS=%JARS%;%1
exit /b

