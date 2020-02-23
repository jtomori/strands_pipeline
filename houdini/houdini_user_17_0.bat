@echo off
rem houdini launcher 

rem version settings
set "HOUDINI_VERSION=17.0.459"
set "RS_VERSION=redshift-2.6.23"
set "HTOA_VERSION=htoa-3.2.2_rdc1beed_houdini-%HOUDINI_VERSION%"

rem source global vars
call \\isilonai\strandsofmind\_pipeline\globals.bat

rem run Houdini
cd ../../
start houdinifx "%~1"