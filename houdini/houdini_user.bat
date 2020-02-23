@echo off
rem houdini launcher 

rem version settings
set "HOUDINI_VERSION=16.5.571"
set "RS_VERSION=redshift-2.6.23"
set "HTOA_VERSION=htoa-3.2.0_r9e1313b_houdini-%HOUDINI_VERSION%"

rem source global vars
call \\isilonai\strandsofmind\_pipeline\globals.bat

rem run Houdini
cd ../../
start houdinifx "%~1"