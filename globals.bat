rem @echo off
rem project global vars

rem set global vars
set "FPS=60"
set "RESX=4096"
set "RESY=2048"
set "ROOT=//isilonai/strandsofmind"
set "PIPELINE=//isilonai/strandsofmind/_pipeline"
set "PIPELINE_WIN=\\isilonai\strandsofmind\_pipeline"
set "HOME=%ROOT%/090_User/%USERNAME%"

rem configure houdini
set "HOUDINI_PATH=%HOUDINI_PATH%;%PIPELINE%/houdini;&"
set "HOUDINI_SCRIPT_PATH=&;" 

set "HOUDINI_SPLASH_FILE=%PIPELINE%/houdini/splash.png"
set "HOUDINI_SPLASH_MESSAGE=| STRANDS OF MIND | Houdini %HOUDINI_VERSION% | %RS_VERSION% | %HTOA_VERSION% | %USERNAME% | %COMPUTERNAME% |"
set "JOB=%ROOT%"
set "HOUDINI_BACKUP_FILENAME=$BASENAME_bak_$N"
set "HOUDINI_BACKUP_DIR=bak"
set "HOUDINI_MAX_BACKUP_FILES=20"
set "HOUDINI_NO_START_PAGE_SPLASH=1"
set "HOUDINI_ANONYMOUS_STATISTICS=0"
set "HOUDINI_DESK_PATH=&;C:/Users/%USERNAME%/Documents/houdini16.5/desktop"
set "HOUDINI_TOOLBAR_PATH=&;C:/Users/%USERNAME%/Documents/houdini16.5/toolbar"
set "HOUDINI_TEMP_DIR=%HOME%/tmp"
set "HOUDINI_BUFFEREDSAVE=1"
set "HOUDINI_IMAGE_DISPLAY_GAMMA=1"
set "HOUDINI_IMAGE_DISPLAY_LUT=%PIPELINE%/houdini/linear-to-srgb_14bit.lut"
set "HOUDINI_IMAGE_DISPLAY_OVERRIDE=1"
set "HOUDINI_ACCESS_METHOD=2"
set "HOUDINI_DSO_ERROR=2"

rem megascans lib
set "MEGA_LIB=%ROOT%/010_Material/020_3D/010_Assets/090_Libraries/010_SOM_Megascans_N/Downloaded"
set "MSL=%MEGA_LIB%"
set "HOUDINI_PATH=%HOUDINI_PATH%;%PIPELINE%/megaH/houdini"

rem rs for houdini
set "RS_ROOT_PATH=%PIPELINE%/%RS_VERSION%"
set "HOUDINI_PATH=%RS_ROOT_PATH%/Plugins/Houdini/%HOUDINI_VERSION%;%HOUDINI_PATH%"
set "PATH=%PATH%;%PIPELINE_WIN%\%RS_VERSION%\bin"
set "REDSHIFT_COREDATAPATH=%RS_ROOT_PATH%"
set "REDSHIFT_LOCALDATAPATH=%HOME%/%COMPUTERNAME%/redshift"
set "REDSHIFT_LICENSEPATH=%PIPELINE%/redshift-lic/"
set "redshift_LICENSE=%PIPELINE_WIN%\redshift-lic\redshift.lic"
set "RR_REDSHIFT_BASE=%RS_ROOT_PATH%"

rem batch converter
set "HOUDINI_PATH=%HOUDINI_PATH%;%PIPELINE%/batch_textures_convert"

rem rv, djv, ps, oiio
set "PATH=%PATH%;C:\Program Files\Tweak\RV\bin;C:\Program Files\djv-1.1.0-Windows-64\bin;C:\Program Files\Adobe\Adobe Photoshop CC 2018;%PIPELINE_WIN%\oiio"

rem create temp dir for houdini user if it does not exist, also convert to forwardslashes
set "TMP_SYS=%TMP%"
set "TMP=%HOUDINI_TEMP_DIR%"
set "TMP=%TMP:/=\%"
IF not exist %TMP% (mkdir %TMP%)

rem htoa
set "HTOA_PATH=%PIPELINE%/htoa/%HTOA_VERSION%"
set "HOUDINI_PATH=%HTOA_PATH%;%HOUDINI_PATH%"
set "ADSKFLEX_LICENSE_FILE=@green"
set "HTOA_PATH=%HTOA_PATH:/=\%"
set "HTOA_AUTOPROP=0"

rem vft
rem set "HOUDINI_PATH=%HOUDINI_PATH%;%PIPELINE%/raymarching/houdini"
set "ARNOLD_PLUGIN_PATH=%ARNOLD_PLUGIN_PATH%;%PIPELINE%/raymarching/osl;%PIPELINE%/raymarching/osl/include"
set "TMP=%TMP_SYS%"

rem set houdini start paths
set "HOUDINI_DIR=C:\Program Files\Side Effects Software\Houdini %HOUDINI_VERSION%\bin"
set "PATH=%PATH%;%HOUDINI_DIR%;%HTOA_PATH%\scripts\bin"