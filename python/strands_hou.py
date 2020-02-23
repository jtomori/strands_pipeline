import re
import hou
import time
import smtplib
import logging
import platform, os, subprocess
from email.mime.text import MIMEText

# logging config
logging.basicConfig(level=logging.DEBUG) # set to logging.INFO to disable DEBUG logs
log = logging.getLogger(__name__)

class SceneUtils(object):
    """
    a class containing utility functions for houdini scene manipulation
    """
    @staticmethod
    def getRenderNodes(node):
        """
        returns renderable nodes found in children of specified node
        """

        node_children = node.allSubChildren()
        node_list = []

        if isinstance(node, hou.RopNode):
            node_list.append(node)
            return node_list
        elif len(node_children) > 0:
            for n in node_children:
                if isinstance(n, hou.RopNode):
                    node_list.append(n)

        if len(node_list) > 0:
            return node_list
        else:
            print("No render node was found.\n")        
            return None

    @staticmethod
    def runAdriansScript(node):
        """
        runs a updateFile() function in hda module of som_filecache node
        """
        if node.type().name() == "som_filecache":
            node.hdaModule().updateFile(node)

    @staticmethod
    def generateBat():
        """
        generates a bat file that will render selected nodes and will submit it at remote windows computers

        users need to have an admin access at the computers in order to use psexec for submitting the job
        
        this tool requires user account password, which is saved in plain text in hou.session once entered

        example command:
            psexec \\Machine_name049 -accepteula -d -l -u domain\user -p pass cmd /c "path\to\bat\embryo_shading_v124_jt.hipnc.bat"
        
        example bat file:
            @echo off &&^
            %RR_ROOT%\bin\win64\rrClientcommander.exe -Abortdisable &^
            call \\isilonai\strandsofmind\_pipeline\houdini\houdini_remote.bat &&^
            pushd \\isilonai\strandsofmind &&^
            cd "020_Preproduction/050_RND/120_bat_testing" &&^
            hbatch -c "render -Va /obj/geo1/rop_geometry1 ; quit" "project_no_rs_v002.hipnc" > "bat\project_no_rs_v002.hipnc.rop_geometry1.bat.log" 2>&1 &&^
            move "bat\project_no_rs_v002.hipnc.rop_geometry1.bat.log" "bat\project_no_rs_v002.hipnc.rop_geometry1.bat.log.finished" &&^
            popd &&^
            %RR_ROOT%\bin\win64\rrClientcommander.exe -Enable
        """
        try:
            node = hou.selectedNodes()[0]
        except IndexError:
            print("No nodes selected.\n")
            return
        
        rop_name = node.name()

        node_top = node
        node = SceneUtils.getRenderNodes(node)
        if node == None:
            return
        else:
            node = node[0]
        SceneUtils.runAdriansScript(node_top)

        rop_path = node.path()

        env_path = os.path.normpath( os.path.join(hou.getenv("PIPELINE"), "houdini/houdini_remote.bat") )

        root_path = hou.getenv("ROOT")
        root_path = os.path.normpath(root_path)

        hip_path = hou.hipFile.path()
        file_name = os.path.split(hip_path)[1]
        
        bat_name = file_name + "." + rop_name + ".bat"

        folder = os.path.split(hip_path)[0]
        folder = folder.replace("S:/","").replace("//isilonai/strandsofmind/","")
        
        bat_folder = os.path.join(root_path, folder, "bat")

        bat_path = os.path.join(bat_folder, bat_name)
        bat_path = os.path.normpath(bat_path)
        
        log_path = bat_name + ".log"
        log_path = os.path.join("bat", log_path)
        log_path = os.path.normpath(log_path)

        log_path_full = os.path.join(bat_folder, bat_name + ".log")
        log_path_full = os.path.normpath(log_path_full)

        bat_script = r'''@echo off &&^
%RR_ROOT%\bin\win64\rrClientcommander.exe -Abortdisable &^
call {0} &&^
pushd {1} &&^
cd "{2}" &&^
hbatch -c "render -Va {3} ; quit" "{4}" > "{5}" 2>&1 &&^
popd &&^
%RR_ROOT%\bin\win64\rrClientcommander.exe -Enable'''.format(env_path, root_path, folder, rop_path, file_name, log_path)
        
        if not os.path.exists(bat_folder):
            os.makedirs(bat_folder)

        with open(bat_path, 'w') as f:
            f.write(bat_script)
        
        #execute = not hou.ui.displayMessage("Batch was written successfully", buttons=('OK', 'NO'), default_choice=0, close_choice=1, help="Would you like to execute it on a remote PC?", title="Batch file generation", details=bat_path, details_label="Show file path", details_expanded=False)

        if platform.system() == "Windows":
            if not hasattr(hou.session, "pwd"):
                pwd = hou.ui.readMultiInput("Enter your aka passowrd", ("Password:",), password_input_indices=(0,), buttons=('OK',), default_choice=0, title="Password", initial_contents=("",))[1][0]
                setattr(hou.session, "pwd", pwd)

            machines = ("Machine_name049", "Machine_name050", "Machine_name051", "Machine_name052", "Machine_name053", "Machine_name054")
            selected = hou.ui.selectFromList(machines, default_choices=(0,), exclusive=True, message="Select one machine:", title="Machine selection", column_header="Machines")[0]

            pc = machines[selected]
            user = hou.getenv("USER")
            pwd = hou.session.pwd
            cmd = "psexec \\\\{0} -accepteula -d -u domain\\{1} -p {2} cmd /c \"{3}\"".format(pc, user, pwd, bat_path)

            # psexec \\Machine_name049 -accepteula -d -l -u domain\user -p pass cmd /c "path\to\bat\embryo_shading_v124_jt.hipnc.bat"
            
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out = "".join(p.communicate())
            print out

            #open_sublime = hou.ui.displayMessage("Job was sent", buttons=('OK', 'NO'), default_choice=0, close_choice=1, help="Would you like to execute it on a remote PC?", title="Batch file generation", details=bat_path, details_label="Show file path", details_expanded=False)

            result = hou.ui.displayMessage("Job was submitted", buttons=("OK", "Open in Sublime"), default_choice=1, close_choice=0, title="Bat submission", details="{}\n{}".format(bat_path, log_path_full), details_label="Show paths")
        
            if result:
                subl_exec = os.path.join(hou.getenv("PIPELINE"), "Sublime", "subl.exe")
                subl_cmd = [subl_exec, log_path_full]
                p = subprocess.Popen(subl_cmd)
        else:
            print("Thise feature works only on Windows")

    @staticmethod
    def mailNotify():
        """
        Sends a notification email, prepared a base, but was not needed anymore
        """
        render_node = hou.pwd()
        render_node_path = render_node.path()
        frame_range_start = int(render_node.evalParm("f1"))
        frame_range_end = int(render_node.evalParm("f2"))
        output_path = render_node.evalParm("sopoutput") 
        user = hou.getenv("USER")
        pc = hou.getenv("COMPUTERNAME")
        scene_file = hou.hipFile.path()
        frames = frame_range_end - frame_range_start + 1

        mail_user = "user"
        mail_from = "user@email.de"
        mail_pwd = "pwd"
        mail_server = "server"
        mail_port = 587

        mail_to = "user2@filmakademie.de"

        text = """Rendering of {0} node was finished
Frame range: {1} - {2} ({7} frames)
Output path: {3}
Scene file: {6}
User: {4}
PC: {5}

With love,
your Strands of Mind Pipeline""".format(render_node_path, frame_range_start, frame_range_end, output_path, user, pc, scene_file, frames)

        msg = MIMEText(text)
        msg["To"] = mail_to
        msg["From"] = mail_from
        msg["Subject"] = "finished {0} | {1}".format(render_node_path, scene_file.replace(hou.getenv("ROOT"),""))

        print msg
        '''
        s = smtplib.SMTP(host=mail_server, port=mail_port)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(mail_user, mail_pwd)
        s.sendmail(mail_from, mail_to, msg.as_string())
        s.quit()
        '''

    @staticmethod
    def verSplit(ver):
        """
        splits version tag into letter and number:
            v028 -> ["v", "028"]
        """
        head = ver.rstrip('0123456789')
        tail = ver[len(head):]
        return head, tail

    @staticmethod
    def incSaveFile(file_name=None):
        """
        incrementally saves current scene
        usernames are shortened, add new users into user_names_mapping dictionoary
        """
        if not file_name:
            path, file_name = os.path.split( hou.hipFile.name() )
        file_name_new = file_name

        name_list = re.split('\.|_|-', file_name)

        user_names_mapping = {
            "ameyer" : "am",
            "jkammere" : "jk",
            "jtomori" : "jt",
            "juraj" : "jt",
            "tvest" : "tv",
            "dschmucker" : "ds",
            "jbraun" : "jb"
        }
        user_name = hou.getenv("USER")

        union = set( user_names_mapping.values() ) & set(name_list)
        if bool( union ):
            found_name = list(union)[0]
            file_name_new = file_name_new.replace(found_name, user_names_mapping[user_name])

        version = None
        version_new = version
        for part in name_list:
            if bool( re.match('^(v|ver|vers|version)([0-9])', part) ) :
                version = part
                ver, num = SceneUtils.verSplit(version)
                num = str( int(num) + 1 ).zfill( len(num) )
                version_new = ver + num
        if not version:
            for part in name_list:
                if bool( re.match('^[0-9]', part) ):
                    version = part
                    version_new = str( int(version) + 1 ).zfill( len(version) )
        
        if version:
            file_name_new = file_name_new.replace(version, version_new)
            new_path = path + "/" + file_name_new
            hou.hipFile.save(new_path)
            #print "saved new file: " + new_path
        else:
            print "No version found in filename, not saving"
    
    @staticmethod
    def openHipFolder():
        """
        Opens folder containing $HIP
        Windows only for now
        """
        path = os.path.normpath(hou.getenv("HIP"))

        if platform.system() == "Windows":
                subprocess.Popen(["explorer", path])
    
    @staticmethod
    def checkParmPath(parm):
        """
        performs series of checks on a parameter object and returns false if it does not pass one of the tests, or true if it passes all of them
        """
        tests = [True]

        parm_eval = parm.eval()
        
        if "\\" in parm_eval:
            tests.append(False)

        skip_strings = ["", "default.bgeo", "Mandril.pic", "pointlight.bgeo", "defcam.bgeo"]
        if len( parm.keyframes() ) == 0:
            parm_raw = parm.unexpandedString()
            if parm_raw not in skip_strings and not parm_raw.startswith("`"):
                if not parm_raw.startswith("$"):
                    tests.append(False)

        return not (False in tests)

    @staticmethod
    def checkAllPaths(kwargs=None):
        """
        checks all paths if they contain backward slashes (\), because this will break linux rendering
        checks paths in parameters without expressions if they are relative - starting with "$" sign

        it traverses specified parameters in specified nodes and prints out suspicious ones, e.g.:
            "file" : {
                "category" : "Sop",
                "parms" : ["file"]
            }
        where file is node type name, category is name of hou.NodeTypeCategory object and parms is list of parameters to check

        alt-clicking on the shelf button enables debug mode which will print more information
        """
        debug = False
        if kwargs:
            if kwargs["altclick"]:
                debug = True
        
        nodes_dict = { 
            "file" : {
                "category" : "Sop",
                "parms" : ["file"]
            },
            "alembic" : {
                "category" : "Sop",
                "parms" : ["fileName"]
            },
            "texture::2.0" : {
                "category" : "Vop",
                "parms" : ["map"]
            },
            "redshift::NormalMap" : {
                "category" : "Vop",
                "parms" : ["tex0"]
            },
            "redshift::TextureSampler" : {
                "category" : "Vop",
                "parms" : ["tex0"]
            },
            "alembicarchive" : {
                "category" : "Object",
                "parms" : ["fileName"]
            },
            "som_filecache" : {
                "category" : "Sop",
                "parms" : ["sopoutput", "file"]
            },
            "som_speedtree_load" : {
                "category" : "Sop",
                "parms" : ["fileName", "custom_dir"]
            },
            "jt_megaLoad_v3" : {
                "category" : "Sop",
                "parms" : ["asset_path", "asset_display_path", "albedo", "bump", "cavity", "fuzz", "roughness", "gloss", "specular", "normal", "normalBump", "displacement", "opacity"]
            },
            "som_rs_speedtree_bark_shd" : {
                "category" : "Vop",
                "parms" : ["moss_tex", "Albedo", "Specular", "Roughness", "Cavity", "Glowmask", "Normal", "Displacement", "Bump", "Opacity"]
            },
            "som_rs_speedtree_leaf_shd" : {
                "category" : "Vop",
                "parms" : ["Albedo", "Specular", "Roughness", "Translucency", "Cavity", "Glowmask", "Normal", "Displacement", "Bump", "Opacity"]
            },
            "som_speedtree_load_obj" : {
                "category" : "Object",
                "parms" : ["RS_archive_file", "RS_objprop_proxy_file"]
            },
            "jt_mega_load_obj" : {
                "category" : "Object",
                "parms" : ["RS_archive_file", "RS_objprop_proxy_file"]
            },
            "som_instance_container_obj" : {
                "category" : "Object",
                "parms" : ["RS_archive_file", "RS_objprop_proxy_file"]
            },
            "som_instance_load_obj" : {
                "category" : "Object",
                "parms" : ["RS_archive_file", "RS_objprop_proxy_file"]
            },
            "som_instance_pack_obj" : {
                "category" : "Object",
                "parms" : ["RS_archive_file", "RS_objprop_proxy_file"]
            }
        }

        found_nodes = []
        for key, value in nodes_dict.iteritems():
            node_type = hou.nodeType( hou.nodeTypeCategories()[ value["category"] ], key )
            if node_type:
                instances = list( node_type.instances() )
                found_nodes.extend( instances )
            else:
                log.warning("Node {} is not available".format(key))
        
        found_parms = []
        for node in found_nodes:
            node_parms = nodes_dict[ node.type().name() ]["parms"]
            for parm in node_parms:
                parm_obj = node.parm(parm)
                if parm_obj:
                    found_parms.append( parm_obj )
                else:
                    log.warning("Parm {} is not available in {}".format(parm, node.path()))
        
        bad_parms = filter(lambda v: not SceneUtils.checkParmPath(v), found_parms)

        if debug:
            print("All parameters: {}\nparameter : evaluated value : raw value".format(len(found_parms)))
            for parm in found_parms:
                if len(parm.keyframes()) <= 1:
                    try:
                        print("{} : {} : {}".format(parm, parm.eval(), parm.unexpandedString()))
                    except hou.OperationFailed:
                        print("{} : {} : {}".format(parm, parm.eval(), parm.expression()))
                else:
                    print("{} : {} : <multiple keyframes>".format(parm, parm.eval()))
                print

            print "\n"*3

        print("Bad parameters: {}\nparameter : evaluated value : raw value".format(len(bad_parms)))
        for parm in bad_parms:
            if len(parm.keyframes()) <= 1:
                try:
                    print("{} : {} : {}".format(parm, parm.eval(), parm.unexpandedString()))
                except hou.OperationFailed:
                    print("{} : {} : {}".format(parm, parm.eval(), parm.expression()))
            else:
                print("{} : {} : <multiple keyframes>".format(parm, parm.eval()))
            print

    @staticmethod
    def convertAllTextures(kwargs=None):
        """
        finds specified texture parameters in the scene, extracts paths and runs batch convert tool with pre-filled paths
        alt-clicking on the shelf button enables debug mode which will print more information

        it finds all instances of nodes specified in node_dict, e.g.
            "redshift::NormalMap" : "Vop",
            "redshift::TextureSampler" : "Vop"
        where Vop is name of hou.NodeTypeCategory object
        
        this depends on batch_textures_convert tool: https://github.com/jtomori/batch_textures_convert/
        """
        debug = False
        if kwargs:
            if kwargs["altclick"]:
                debug = True

        parm_name = "tex0"

        node_dict = {
            "redshift::NormalMap" : "Vop",
            "redshift::TextureSampler" : "Vop"
        }
        
        found_nodes = []
        for key, value in node_dict.iteritems():
            node_type = hou.nodeType( hou.nodeTypeCategories()[value], key )
            if node_type:
                instances = list( node_type.instances() )
                found_nodes.extend( instances )

        found_parms = []
        for node in found_nodes:
            found_parms.append( node.parm(parm_name) )

        found_texture_dirs = []
        for parm in found_parms:
            parm_value = parm.eval()
            if parm_value != "":
                dir_path = os.path.dirname( os.path.abspath( parm_value ) )
                found_texture_dirs.append( dir_path )
                if debug:
                    print("{} : {}".format(parm, dir_path))

        found_texture_dirs = list( set(found_texture_dirs) )

        try:
			import batch_convert
			batch_convert.runGui(path=batch_convert.paths_separator.join( found_texture_dirs ))
        except ImportError:
            log.error("batch_convert module could not be imported")

class VCAUtils(object):
    """
    A class containing functions for managing VCA remote rendering
    """
    @staticmethod
    def submitToVCA():
        """
        Submits selected nodes to VCA machine.
        It also creates a folder for logs, where submitted jobs will store its output. Finished logs are renamed.
        Multiple jobs don't render at the same time, but wait till there is no job running, multiple jobs will render in random order.

        testing command:
            plink -batch -ssh -hostkey host_key -pw secret_pwd user@machine "ls && pwd"

        example cmomand:
            \\isilonai\strandsofmind\_pipeline\utils\plink.exe -batch -ssh -hostkey host_key -pw secret_pwd user@machine "while pgrep hbatch-bin > /dev/null; do sleep 5; done && cd $ROOT && cd ""020_Preproduction/050_RND/510_rs_farm_vca_testing/WORK"" && hbatch -c ""render -Va /out/rs_shading_stage_lq ; quit"" ""rs_farm_vca_testing_v014_jt.hipnc"" &> vca/rs_farm_vca_testing_v014_jt.hipnc.rs_shading_stage_lq.log && mv ""vca/rs_farm_vca_testing_v014_jt.hipnc.rs_shading_stage_lq.log"" ""vca/rs_farm_vca_testing_v014_jt.hipnc.rs_shading_stage_lq.log.finished"" " 
        """
        nodes = hou.selectedNodes()
        if not bool( nodes ):
            print("No nodes selected.\n")
            return

        logs = []

        # do a check if there are archive parameters on, store them and disable them
        enabled_archive_parms = []
        for node in nodes:
            if node.type().name() == "Redshift_ROP":
                archive_parm = node.parm("RS_archive_enable")
                if archive_parm.eval() == 1:
                    enabled_archive_parms.append(archive_parm)
                    archive_parm.set(0)
                    log.warning('Temporarily disabling "RS_archive_enable" parameter in "{}"'.format(node.path()))

        hou.hipFile.save()

        for node in nodes:
            node_top = node
            node = SceneUtils.getRenderNodes(node)
            if node == None:
                return
            else:
                node = node[0]
            SceneUtils.runAdriansScript(node_top)

            rop_path = node.path()
            rop_name = node_top.name()

            hip_path = hou.hipFile.path()
            file = os.path.split(hip_path)[1]
            folder = os.path.split(hip_path)[0]

            log_folder = os.path.join(folder, "vca")
            log_folder = os.path.normpath(log_folder)
            log_file = file + "." + rop_name + ".log"
            log_file_finished = log_file + ".finished"
            folder = folder.replace("S:/","").replace("//isilonai/strandsofmind/","")
            wait_cmd = "while pgrep hbatch-bin > /dev/null; do sleep 5; done"

            #linux_cmd = """{5} && cd $ROOT && cd "{0}" && hbatch -c "render -Va {1} ; quit" "{2}" &> vca/{3} && mv "vca/{3}" "vca/{4}" """.format(folder, rop_path, file, log_file, log_file_finished, wait_cmd) # rename log after finished
            linux_cmd = """{4} && cd $ROOT && cd "{0}" && hbatch -c "render -Va {1} ; quit" "{2}" &> vca/{3}""".format(folder, rop_path, file, log_file, wait_cmd)            
            linux_cmd = linux_cmd.replace("\"","\"\"")

            plink_path = os.path.join(hou.getenv("PIPELINE"), "utils", "plink.exe")
            plink_path = os.path.normpath(plink_path)
            cmd = """{0} -batch -ssh -hostkey host_key -pw secret_pwd user@machine "{1}" """.format(plink_path, linux_cmd)
            
            if not os.path.exists(log_folder):
                os.makedirs(log_folder)

            if platform.system() == "Windows":
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            print cmd
            logs.append(os.path.join(log_folder,log_file))

            time.sleep(0.2)

        # enable temporarily disabled archive parameters back
        for parm in enabled_archive_parms:
            parm.set(1)

        result = hou.ui.displayMessage("{0} jobs were submitted to VCA".format(len(logs)), buttons=("OK", "Open in Sublime"), default_choice=1, close_choice=0, title="VCA submissions", details="\n".join(logs), details_label="Show log paths")
        
        if result:
            subl_exec = os.path.join(hou.getenv("PIPELINE"), "Sublime", "subl.exe")
            subl_cmd = [subl_exec] + logs
            if platform.system() == "Windows":
                p = subprocess.Popen(subl_cmd)
    
    @staticmethod
    def killAllVCAJobs():
        """
        Sends a command to VCA which will kill all processes, which have "hbatch-bin" in their command

        Example command:
            \\isilonai\strandsofmind\_pipeline\utils\plink.exe -batch -ssh -hostkey host_key -pw secret_pwd user@machine "ps -x | grep -i hbatch-bin | awk {'print $1'} | xargs kill -9" 
        """
        plink_path = os.path.join(hou.getenv("PIPELINE"), "utils", "plink.exe")
        plink_path = os.path.normpath(plink_path)
        
        linux_cmd = "ps -x | grep -i hbatch-bin | awk {'print $1'} | xargs kill -9"
        linux_cmd = linux_cmd.replace("\"","\"\"")

        cmd = """{0} -batch -ssh -hostkey host_key -pw secret_pwd user@machine "{1}" """.format(plink_path, linux_cmd)

        if platform.system() == "Windows":
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        print cmd
    
    @staticmethod
    def listAllVCAJobs():
        """
        Sends a command to VCA which will list all processes, which have "while pgrep hbatch-bin" in their command

        Example command:
            \\isilonai\strandsofmind\_pipeline\utils\plink.exe -batch -ssh -hostkey host_key -pw secret_pwd user@machine "ps -x -o command | grep -i ""while pgrep hbatch-bin"" "
        
        For formatting - example output:
            bash -c while pgrep hbatch-bin > /dev/null; do sleep 5; done && cd $ROOT && cd "020_Preproduction/050_RND/510_rs_farm_vca_testing/WORK" && hbatch -c "render -Va /out/rs_shading_stage_lq ; quit" "rs_farm_vca_testing_v018_jt.hipnc" &> vca/rs_farm_vca_testing_v018_jt.hipnc.rs_shading_stage_lq.log && mv "vca/rs_farm_vca_testing_v018_jt.hipnc.rs_shading_stage_lq.log" "vca/rs_farm_vca_testing_v018_jt.hipnc.rs_shading_stage_lq.log.finished" 

        """
        plink_path = os.path.join(hou.getenv("PIPELINE"), "utils", "plink.exe")
        plink_path = os.path.normpath(plink_path)
        
        linux_cmd = """ps -x -o command | grep -i "while pgrep hbatch-bin" """
        linux_cmd = linux_cmd.replace("\"","\"\"")

        cmd = """{0} -batch -ssh -hostkey host_key -pw secret_pwd user@machine "{1}" """.format(plink_path, linux_cmd)

        if platform.system() == "Windows":
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out = "".join(p.communicate())
        print cmd

        filtered = []
        for line in out.split("\n"):
            if "while pgrep hbatch-bin > /dev/null; do sleep 5;" in line:
                line = line.replace('bash -c while pgrep hbatch-bin > /dev/null; do sleep 5; done && cd $ROOT && cd "', "")
                line = line.replace('" && hbatch -c "render -Va', "")
                line = line.replace('; quit" "', "")
                line = line.split('" &> vca/')[0]
                line = line.split(" ")
                line[0], line[1] = line[0] + "/" + line[2], line[1]
                #line[0], line[1], line[2] = line[0], line[2], line[1]
                #line[0] = line[0] + "/"
                line = ": ".join(line[:2])
                filtered.append(line)
        
        hou.ui.displayMessage("There were found {} jobs".format(len(filtered)), title="VCA submissions list", details="\n".join(filtered), details_label="Show output")

class MegaUtils(object):
    """
    a class containing functions for managing megaH plugin
    """
    @staticmethod
    def getChildMegaLoad(node):
        """
        finds fist mega load node inside of this node
        """
        mega_load_node = None
        mega_load_node = node.glob("mega_load")[0]
        
        return mega_load_node
    
    @staticmethod
    def getChildMatnet(node):
        """
        finds fist Material SOP node inside of this node
        """
        out_node = None
        out_node = node.glob("matnet")[0]
        
        return out_node
    
    @staticmethod
    def getChildMaterialAssign(node):
        """
        finds fist Material SOP node inside of this node
        """
        mat_node = None
        mat_node = node.glob("material_assign")[0]
        
        return mat_node

    @staticmethod
    def renameMegaLoadObj(node=None):
        """
        sets current node name to child mega load node's comment
        """
        if not node:
            node = hou.pwd()
        
        mega_load_name = "Not_found"
        mega_load_node = MegaUtils.getChildMegaLoad(node)
        if mega_load_name:
            mega_load_name = mega_load_node.comment()
        else:
            log.warning("no mega load node found inside of this node")
        
        node.setName(mega_load_name, unique_name=True)
    
    @staticmethod
    def setProxyPath(node=None):
        """
        sets proxy path in mega load obj asset to exported RS file path and preserves some variables
        """
        if not node:
            node = hou.pwd()
        
        root_path = os.path.normpath( hou.getenv("ROOT") ).replace("\\","/")

        hip_path = os.path.normpath( hou.expandString("$HIP") ).replace("\\","/").replace("S:/","//isilonai/strandsofmind/", 1)
        hip_path = hip_path.replace(root_path, "$ROOT")

        out_path = node.parm("RS_archive_file").unexpandedString()

        out_path = out_path.replace("$HIPNAME", hou.expandString("$HIPNAME") )
        out_path = out_path.replace("$HIP", hip_path )
        out_path = out_path.replace("$OS", hou.expandString("$OS") )

        node.parm("RS_objprop_proxy_file").set(out_path)
    
    @staticmethod
    def megaObjDuplicate(node=None, mode="lod"):
        """
        duplicates selected node with selected LODs
        """
        if not node:
            node = hou.pwd()
        
        if mode == "lod":
            set_parm = "asset_lod"
            select_message = "Select LODs to be created"
            select_title = "Select LODs"
        elif mode == "asset":
            set_parm = "asset"
            select_message = "Select asset variations to be created"
            select_title = "Select variations"
        else:
            log.error("wrong mode set")
            return

        node_pos = node.position()

        mega_load_node = MegaUtils.getChildMegaLoad(node)
        if not mega_load_node:
            log.error("no mega load node found inside of this node")
            return

        editor = hou.ui.paneTabOfType(hou.paneTabType.NetworkEditor)
        orig_path = editor.pwd().path()

        my_shader_node = MegaUtils.getChildMaterialAssign(node)
        my_shader_multiparm = my_shader_node.parm("num_materials")
        my_shader_multiparms = my_shader_multiparm.multiParmInstances()

        my_matnet = MegaUtils.getChildMatnet(node)
        my_matnet_children = my_matnet.children()

        my_lods_parm = mega_load_node.parm( set_parm )
        lods = my_lods_parm.menuItems()
        my_lod = lods[ my_lods_parm.eval() ]
        lods = list( set(lods) - set([my_lod]) )
        lods.sort()

        selected = hou.ui.selectFromList(choices=lods, message=select_message, title=select_title, clear_on_cancel=True)
        if len(selected) == 0:
            return
        
        lods = [ lods[i] for i in selected]

        for i, lod in enumerate(lods):
            new_node = hou.copyNodesTo((node, ), node.parent())[0]
            new_node.setPosition( node_pos + hou.Vector2( (1 * i + 1, -1 * i - 1) ) )
            mega_node_child = MegaUtils.getChildMegaLoad(new_node)
            
            child_lods = mega_node_child.parm( set_parm ).menuItems()
            mega_node_child.parm( set_parm ).set( child_lods.index(lod) )
            mega_node_child.parm("reload").pressButton()
            new_node.parm("rename").pressButton()

            new_node_shader = MegaUtils.getChildMaterialAssign(new_node)
            new_node_shader_multiparm = new_node_shader.parm("num_materials")
            new_node_shader_multiparm.setFromParm(my_shader_multiparm)
            new_node_shader_multiparms = new_node_shader_multiparm.multiParmInstances()
            for i, parm in enumerate(new_node_shader_multiparms):
                try:
                    if parm.parmTemplate().stringType() == hou.stringParmType.NodeReference:
                        path = my_shader_multiparms[i].evalAsNode().path()
                        parm.set(path)
                    else:
                        parm.setFromParm( my_shader_multiparms[i] )
                except AttributeError:
                    parm.setFromParm( my_shader_multiparms[i] )
            
            new_matnet = MegaUtils.getChildMatnet(new_node)
            new_matnet_children = new_matnet.children()
            for new_matnet_child in new_matnet_children:
                new_matnet_child.destroy()
            new_matnet.copyItems(my_matnet_children)
        
        node.setColor( hou.Color((0, 0, 0)) )        
        
        editor.cd(orig_path)
    
    @staticmethod
    def expandInstanceFile(node=None):
        """
        expands s@instancefile point attribute to a full path
        """
        if not node:
            node = hou.pwd()

        geo = node.geometry()
        attrib_name = "instancefile"

        attribs_tuple = geo.pointStringAttribValues(attrib_name)
        attribs_expanded_list = list(attribs_tuple)

        for i, path in enumerate(attribs_expanded_list):
            path = hou.expandString(path)
            path = os.path.normpath(path).replace("\\", "/")
            attribs_expanded_list[i] = path

        geo.setPointStringAttribValues(attrib_name, tuple( attribs_expanded_list ))