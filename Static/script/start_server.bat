@echo off
SET "current_dir=%~dp0"
echo Current directory: %current_dir%

cd %current_dir%
cd ..\..

SET "app_dir=%cd%"
echo App directory: %app_dir%

echo Attempting to start the server now...
start python "%app_dir%\app.py"

echo Flask Server should now be running.
exit
