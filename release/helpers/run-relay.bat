@echo off
REM run-relay.bat - start a PhiNET relay on Windows. Open port 7700 inbound first.
set HERE=%~dp0
set PHINET_HOME=%USERPROFILE%\.phinet
if not exist "%PHINET_HOME%" mkdir "%PHINET_HOME%"
"%HERE%bin\phinet-daemon.exe" ^
  --host 0.0.0.0 --port 7700 ^
  --identity "%PHINET_HOME%\.phinet\identity.json" ^
  --consensus-url http://phinetproject.com/phinet/consensus.json ^
  --consensus-http-version 1.1 ^
  --bootstrap phinetproject.com:7700 ^
  --bootstrap lobarcs.com:7700 ^
  --bootstrap libraryofaletheia.com:7700 ^
  --trusted-authority af1aebff73f4bc25cb593481c78ca0b80f4c016237a1c896eff3656995f2cf3c ^
  --trusted-authority 7c30f0d91e8cb9263d13425e662f646fe50beaebceb84e1f3cc0fa525a6dc512 ^
  --trusted-authority 901e2740560270bb128b5c4d0cb8666a2cc525f87a9b75fb31bc8d94f2332ce8
