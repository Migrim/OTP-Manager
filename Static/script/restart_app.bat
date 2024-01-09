@echo off
SET "current_dir=%~dp0"
echo Current directory: %current_dir%

cd %current_dir%
cd ..\..

SET "app_dir=%cd%"
echo App directory: %app_dir%

echo Waiting for 10 seconds before attempting to restart the server...
timeout /t 10

echo Attempting to restart the server now...
start python "%app_dir%\app.py"

echo Server restart script has finished.
exit
