@echo off
rem RR Submitter for Mandelbulber 2, in Keyframe mode
rem change CompanyProjectName setting for your project

%RR_ROOT%\bin\win64\rrStartlocal rrSubmitter "%~1" -Software "Mandelbulber" -Version "2.14" -Renderer "Keyframe" -Layer "Scene" -ImageDir "<SceneFolder>\\<Scene>_render" -ImageFileName "frame_" -ImageFramePadding 7 -ImageExtension ".exr" -SeqStart 0 "SequenceDivide=1~1" "SeqDivMIN=1~1" "SeqDivMAX=1~5" "PPSequenceCheck=1~0" "PPCreateSmallVideo=1~0" "RenderPreviewFirst=1~0" "CompanyProjectName=0~strandsofmind"
