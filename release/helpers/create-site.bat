@echo off
REM create-site.bat <name> <folder> - publish a .phinet site on Windows.
set HERE=%~dp0
set PHINET_HOME=%USERPROFILE%\.phinet
if "%~1"=="" ( echo usage: create-site.bat ^<name^> ^<folder^> & exit /b 1 )
if "%~2"=="" ( echo usage: create-site.bat ^<name^> ^<folder^> & exit /b 1 )
"%HERE%bin\phi.exe" new %1
echo(
echo Copy the .phinet address above, then deploy with:
echo   "%HERE%bin\phi.exe" deploy ^<hs_id^> %2
