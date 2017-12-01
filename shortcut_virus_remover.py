#!/usr/bin/env python3

#Wed 15 Nov 2017 12:47:46 AM GMT 

#===========================================================================================
# Copyright (C) 2017 Nafiu Shaibu.
# Purpose: Short cut virus removal and files recovery
#-------------------------------------------------------------------------------------------
# This is a free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your option)
# any later version.

# This is distributed in the hopes that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#===========================================================================================

import os, sys, time
import re, glob, platform
import sys, shutil, getopt
import subprocess, string
import threading
import logging as logs

os_type = platform.system()

if os_type == "Windows":
	'''Microsoft windows system commands'''
	windows_cmd = {'ATTRIB': ["attrib", "-r", "-a", "-h", "/s", "/d"], 'KILL': ["taskkill", "/f", "/t", "/im"],
                  'R_FIND': ["reg query"], 'R_DELETE': ["reg delete"], 'R_RADD': ["reg add"]
                 }

	try:
		import ctypes
	except ImportError as err:
		print("ImportError: %s" % err.args)
		print("Install the module and try again !!!")
		sys.exit(0)
		
		
	def read_partitions(drive_list=None):
		drive = []
		if drive_list is None: drive_list = []
		
		mask = ctypes.windll.kernel32.GetLogicalDrives()
		for driv_letter in string.ascii_uppercase:
			if mask & 1:
				pdrive = ":".join([str(driv_letter), "\\"])
				if not pdrive in drive_list:
					drive.append( pdrive )
			mask >>= 1
		
		return drive

	def enable_windows_system_softwares():
		'''Enables task manager and regedit'''

		try:
			'''' Constructing window registry command for enabling TaskMgr for LOCAL_MACHINE root key'''
			windows_cmd["R_ADD"].extend(["HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
										 "/v DisableTaskMgr", "/t", "REG_DWORD", "/d 0", "/f"])

			subprocess.check_call(windows_cmd["R_ADD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		except subprocess.CalledProcessError as err_hklm:
			print("[HKLM]: enabling TaskManager failed with errcode: %d" % err_hklm)

		try:
			'''Constructing windows registry command for enabling TaskMgr for CURRENT_USER root key'''
			windows_cmd["R_ADD"].clear()
			windows_cmd["R_ADD"].extend(["reg add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
										 "/v DisableTaskMgr", "/t REG_DWORD", "/d 0", "/f"])

			subprocess.check_call(windows_cmd["R_ADD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		except subprocess.CalledProcessError as err_hkcu:
			print("[HKCU]: enabling TaskManager failed with errcode: %d" % err_hkcu)

		try:
			'''Command for enable regedit for LOCAL_MACHINE root key'''
			windows_cmd["R_ADD"].clear()
			windows_cmd["R_ADD"].extend(["reg add", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
										 "/v DisableRegistryTools", "/t REG_DWORD", "/d 0", "/f"])

			subprocess.check_call(windows_cmd["R_ADD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		except subprocess.CalledProcessError as err_reg_hklm:
			print("[HKLM]: enabling Regedit failed with errcode: %d" % err_reg_hklm)
			
		try:
			'''Command for enable regedit for CURRENT USER root key'''
			windows_cmd["R_ADD"].clear()
			windows_cmd["R_ADD"].extend(["reg add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
										 "/v DisableRegistryTools", "/t REG_DWORD", "/d 0", "/f"])

			subprocess.check_call(windows_cmd["R_ADD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		except subprocess.CalledProcessError as err_reg_hkcu:
			print("[HKCU]: enabling TaskManager failed with errcode: %d" % err_reg_hkcu)

		finally:
			windows_cmd["R_ADD"].clear()
			windows_cmd["R_ADD"].append("reg add")


	def clean_windows_registry():
		pass

elif os_type == "Linux":
	try:
		import pyudev
		import psutil			#partition imports
	except ImportError as err:
		print("ImportError: %s" % err.args)
		print("Install the module and try again !!!")
		sys.exit(0)

	def read_partitions(drive_list=None):
		drive = []
		if drive_list is None: drive_list=[]

		partitions = psutil.disk_partitions()
		for part in partitions:
			if not str(part.mountpoint) in drive_list:
				drive.append(part.mountpoint)

		return drive  # return drive list

VIRUS_DIR = "Drive"
VIRUS_FILE = "Drive.bat"
DELAY = 0.2
OS_DIR_SEP = os.sep

'''The log file for the application'''
log_filename = OS_DIR_SEP.join([os.path.expanduser('~'), "shortcut_virus.log"])

''' 
    This defines the amount of time to wait for the os to setup stuffs for the app to detect.
	This is used in the polling function in USBDeviceDetectionAndProtection class
'''
RATE_OF_DETECTION = 5 #for linux os

'''This defines the amount of time a thread is require to wait before the next scan'''
THREAD_WAIT_PERIOD = 7

try: PID = os.getpid()
except: PID = -20

info_b = b'\xff\xfe\x00\x00C\x00\x00\x00o\x00\x00\x00p\x00\x00\x00y\x00\x00\x00r\x00\x00\x00i\x00\x00\x00g\x00\x00\x00h\x00\x00\x00t\x00\x00\x00 \x00\x00\x00(\x00\x00\x00C\x00\x00\x00)\x00\x00\x00 \x00\x00\x002\x00\x00\x000\x00\x00\x001\x00\x00\x007\x00\x00\x00 \x00\x00\x00N\x00\x00\x00a\x00\x00\x00f\x00\x00\x00i\x00\x00\x00u\x00\x00\x00 \x00\x00\x00S\x00\x00\x00h\x00\x00\x00a\x00\x00\x00i\x00\x00\x00b\x00\x00\x00u\x00\x00\x00[\x00\x00\x00g\x00\x00\x00i\x00\x00\x00t\x00\x00\x00h\x00\x00\x00u\x00\x00\x00b\x00\x00\x00.\x00\x00\x00c\x00\x00\x00o\x00\x00\x00m\x00\x00\x00/\x00\x00\x00n\x00\x00\x00s\x00\x00\x00h\x00\x00\x00a\x00\x00\x00i\x00\x00\x00b\x00\x00\x00u\x00\x00\x00]\x00\x00\x00.\x00\x00\x00'


def validate_dir_path(dir_path):
	'''Validate the directory path'''
	if dir_path == "":
		return True
	else:
		if os_type == "Linux":
			return not re.match(r'^/(\D|\d)*', dir_path) is None
		elif os_type == "Windows":
			return not re.match(r'^\D:\\(\D|\d)*', dir_path) is None

def usb_autorun_basicvirus_remover(path, virus_not_removed_list):
	'''remove auto run virus for drives'''
	autorun_viruses = ["ravmon.exe", "ntdelect.com", "new folder.exe", "kavo.exe", "autorun.inf",
                       "newfolder.exe", "scvvhsot.exe", "scvhsot.exe", "hinhem.scr", "scvhosts.exe",
                       "new_folder.exe", "regsvr.exe", "svichossst.exe", "autorun.ini", "blastclnnn.exe",
                       "csrss.exe"
                     ]  #"arona.exe", "logon.bat"

	ppath = os.path.normpath(path)

	if os.path.isfile(ppath):
		if re.match(r'^C:\\Windows\\System(32|64)\\Csrss.exe', ppath, re.IGNORECASE): return   #if is csrss is in system path return

		if ppath[0:2].lower() == "c:" and \
			not re.match(r'^C:\\Windows(\\System(32|64))*\\Ravmon.exe', ppath, re.IGNORECASE) is None:  #if revmon is found in c:windows folder then is 90% malware
			return

		basename = shutil._basename(ppath)
		try:
			autorun_viruses.index(basename.lower())

			if os_type == "Windows":
				windows_cmd['KILL'].append(basename)
				subprocess.check_call(windows_cmd['KILL'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) # Kill process if running
				windows_cmd['KILL'].pop()
				
		except ValueError:
			return
		except subprocess.CalledProcessError:   #can't block deleting the file
			pass

		try: os.unlink(ppath)
		except:
			virus_not_removed_list.append(ppath)


def find_file(fname, dir_path):
	file_path = list()

	for files in os.listdir(dir_path):
		if fname in files:
			file_path.append(dir_path)
			file_path.append(fname)
			break
	if file_path:
		return OS_DIR_SEP.join(file_path)
	else:
		return None


def move_user_data(dataTomove, userdir, _file_):
	if not os.path.exists(userdir):
		os.makedirs(userdir)
	try:
		shutil.move(dataTomove, userdir)
	except:
		_file_.append(dataTomove)

class RealTimeScanner(threading.Thread):
	'''This class creates a thread to handle any usb device inserted'''
	
	def __init__(self, thid, drive_name, drive_list, lockdatastruct):
		threading.Thread.__init__(self)
		self.threadId = thid
		self.param = (drive_name, drive_list, lockdatastruct)

		self.deepScanner = DeepVirusScanner()
		self.shallowScanner = VirusScanner()

		
	def run(self):
		num_times_run = 0

		while True:
			if self.param.__len__() != 3: return
			drive = self.param[0]
			drive_lt = self.param[1]
			lockstruct = self.param[2]

			print("[Thread %d]: Checking partition %s" % (self.threadId, str(drive)) )
			if drive in drive_lt:
				if num_times_run == 0:
					try:
						self.deepScanner.scan_all_dirs(drive, enable_usbbasicvirus_scan=True)

						if not self.deepScanner.is_all_virus_removed():
							lockstruct.acquire(blocking=1)
							logs.critical(" ".join(["These files are suspicion", str(self.deepScanner.get_virus_not_removed())] ))
							lockstruct.release()

							self.deepScanner.get_virus_not_removed().clear()
					except: 
						return
				else:
					try: self.shallowScanner.check_for_virus(drive)
					except: return
			else:
				print("[Thread %d]: Partition:%s Exiting!!!" % (self.threadId, str(drive)) )
				return

			time.sleep(THREAD_WAIT_PERIOD)
			num_times_run += 1


class USBDeviceDetectionAndProtection:
	def __init__(self, _num_, drive):
		self.drives = drive        #All drives or partitions inserted
		self.drive_added = list()  #All recent drives or partitions inserted
		self.num_of_drives = _num_ #Number of drives or partition mounted recently

		self.threadLock = threading.Lock()   #lock object for threads and main
		self.threadList = list()			 #list of created threads

		logs.basicConfig(format="%(asctime)s %(levelname)s:%(message)s", filename=log_filename, level=logs.DEBUG)

	def getSize(self):
		'''get number of drives attached'''
		return self.drives.__len__()

	def getdrives(self):
		'''check for usb drive to system'''
		
		drives = read_partitions(self.drives)
		if not drives == []:
			for drive in drives: self.drives.append(drive)

		return len(self.drives)

	def poll_on_usbdevices(self, ptime=0.5):
		'''
			listen whether new usb device has been attached to the computer system and start a thread to
			clean it up. The polling waste a lot of cpu time. However, this is what i can implement for now
		'''
		id = 0
		if os_type == "Windows":
			prev_len = self.getdrives()
			
			print("[MAIN THREAD]:[PARTITIONS: %d] Listening for USB devices ..." % self.getdrives())
			while True:
				self.drives = read_partitions()
				next_len = len(self.drives)
				cond_variable = next_len - prev_len
				
				if cond_variable < 0:
					prev_len += cond_variable
					cond_variable = abs(cond_variable)
				
				if cond_variable > 0:
					'''spawn threads here: get drive letters here'''
					print("[MAIN THREAD]:[PARTITIONS: %d] Listening for USB devices ..." % next_len)
					
					for index in range(cond_variable):
						try:
							thread_obj = RealTimeScanner(id, self.drives[prev_len + index], self.drives, self.threadLock)
							thread_obj.start()
							self.threadList.append(thread_obj)
							id += 1
						except Exception as e:
							self.threadLock.acquire(blocking=1)
							logs.info(" ".join(["Error occurred while starting thread", str(e.args)]))
							self.threadLock.release()
				else:
					time.sleep(ptime)
				prev_len = next_len
		elif os_type == "Linux":

			context = pyudev.Context()
			monitor = pyudev.Monitor.from_netlink(context)
			monitor.filter_by(subsystem="usb")

			print("[MAIN THREAD]:[PARTITIONS: %d] Listening for USB devices ..." % self.getdrives())
			for device in iter(monitor.poll, None):
				print("[MAIN THREAD]:[PARTITIONS: %d] Listening for USB devices ..." % self.getdrives())

				if device.action == 'add':
					time.sleep(RATE_OF_DETECTION)    ## wait for os to mount device
					self.drive_added = [self.drives[index + self.num_of_drives] for index in range(self.getdrives() - self.num_of_drives)]

					if not self.drive_added == []:
						for partition in self.drive_added:
							try:
								thread_obj = RealTimeScanner(id, os.path.normpath(partition), self.drives, self.threadLock)
								thread_obj.start()
								id += 1
							except Exception as e:
								self.threadLock.acquire(blocking=1)
								logs.info(" ".join(["Error occurred while starting thread", str(e.args)]))
								self.threadLock.release()

					self.num_of_drives = self.getdrives()

				elif device.action == 'remove':
					time.sleep(RATE_OF_DETECTION)
					self.drives = read_partitions()
					self.num_of_drives = len(self.drives)


class VirusScanner:
	def __init__(self):
		self.root_path = os.getcwd()
		self.batch_file_path = None			#virus startup batch file
		self.virus_files = list()
		self.virus_dir = list()
		self.files_not_retrieved = list()     #files not retrieved from virus directory
		self.user_data_dir = OS_DIR_SEP.join([str(self.root_path), "YourFiles" + str(PID)])
		
	def set_root_path(self, path):
		if not os.path.isdir(path): return False
		else:
			self.root_path = path
			return True
#setters and getters
	def set_batch_file_path(self, path):
		self.batch_file_path = path

	def set_user_data_path(self, path):
		self.user_data_dir = path

	def get_batch_file_path(self):
		return os.path.normpath(self.batch_file_path)

	def get_user_data_path(self):
		return os.path.normpath(self.user_data_dir)

	def get_root_path(self):
		return os.path.normpath(self.root_path)
#end of setters and getters

	def check_is_affected(self):
		self.batch_file_path = find_file(VIRUS_FILE, self.root_path)
		return not self.batch_file_path == None
			
		
	def check_for_virus(self, path=os.getcwd()):
		for entry in os.listdir(os.path.normpath(path)):
			if os.path.isdir(OS_DIR_SEP.join([path, entry])) and entry == VIRUS_DIR:

				for subentry in os.listdir(os.path.normpath(OS_DIR_SEP.join([self.root_path, VIRUS_DIR]))):
					files_name = os.path.normpath(OS_DIR_SEP.join([self.root_path, VIRUS_DIR, subentry]))

					if os.path.isdir(files_name) and subentry.isdigit():
						print("\nCHECKING " + subentry + " ...")
						files_in_dir = os.listdir(files_name)
						i = 0
						
						if files_in_dir:
							while i < len(files_in_dir):
								if re.match(r'\D*\.js$', files_in_dir[i], re.IGNORECASE):
									self.virus_files.append(files_in_dir[i])
									self.virus_dir.append(OS_DIR_SEP.join([files_name, files_in_dir[i]]))
								i += 1
						else:
							print("[%d]:Retrieving %s" % (PID, subentry))
							move_user_data(files_name, self.get_user_data_path(), self.files_not_retrieved)
					else:
						print("[%d]:Retrieving %s" % (PID, subentry))
						move_user_data(files_name, self.get_user_data_path(), self.files_not_retrieved)
				break
						

class DeepVirusScanner:
	def __init__(self):
		self.virusscanner = VirusScanner()
		self.virus_not_removed_list = []      #basic usb viruses not removed

	def get_virus_not_removed(self):
		return self.virus_not_removed_list

	def is_all_virus_removed(self):
		return len(self.virus_not_removed_list) == 0

	def scan_all_dirs(self, dirp=os.getcwd(), enable_usbbasicvirus_scan=False):

		for root, dirs, files in os.walk(os.path.normpath(dirp)):

			if files == []: return
			else:
				try:
					print(" ".join(["Checking for virus in", dirp]) )
				except UnicodeEncodeError:
					pass
					
				for file in files:
					if file == VIRUS_FILE or os.path.isdir(os.path.normpath(OS_DIR_SEP.join([dirp, VIRUS_DIR]))):
						self.virusscanner.set_batch_file_path(os.path.normpath(OS_DIR_SEP.join([dirp, VIRUS_FILE])))
						print("[%d]:%s %s" % (PID, "Virus found at ", self.virusscanner.get_batch_file_path()))
						print("[%d]:%s" % (PID, "Removing the virus file"))
						try:
							os.remove(self.virusscanner.get_batch_file_path())
						except:
							pass
						time.sleep(DELAY)

						print("[%d]:%s" % (PID, "Removing shortcuts"))
						p = re.match(r'(\D|\d)*[\\/]+[Dd][Ee][Ss][Kk][Tt][Oo][Pp]$', dirp, re.IGNORECASE)
						if not p:
							for shortcut in glob.glob(OS_DIR_SEP.join([dirp, "*.lnk"])):
								os.remove(os.path.normpath(shortcut))
						time.sleep(DELAY)

						self.virusscanner.set_root_path(os.path.normpath(dirp))
						self.virusscanner.set_user_data_path(OS_DIR_SEP.join([dirp, "YourFiles" + str(PID)]))

						self.virusscanner.check_for_virus(os.path.normpath(dirp))

						virusdir = OS_DIR_SEP.join([dirp, VIRUS_DIR])
						if os.path.exists(virusdir) and not self.virusscanner.virus_files == []:
							try:
								if not self.virusscanner.files_not_retrieved == []: raise OSError("Files not retrieved")
								
								try: shutil.rmtree(virusdir, ignore_errors=True)
								except: pass
							except OSError as e:
								'''
									Ensuring the safety criticality such that user files are
									not deleted mistakenly. That is if it fails to retrieve
									all user files it backtrack into this level.
								'''
								print("[%d]%s" % (PID, ": ".join([str(e.arg), str(self.virusscanner.files_not_retrieved)])))

								if os_type == "Windows":
									print("[%d]:%s" % (PID, "Changing the virus directory attributes"))

									try:
										windows_cmd['ATTRIB'].append(virusdir)
										subprocess.check_call(windows_cmd['ATTRIB'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
										windows_cmd['ATTRIB'].pop()
										
									except subprocess.CalledProcessError as e:
										print("ERROR: Failed to start process errcode=%d" % e.arg )

								print("[%d]: %s" % (PID, "Removing virus traces ..."))
								for fpath in self.virusscanner.virus_dir:
									try: os.unlink(fpath)
									except: pass

								os.rename(OS_DIR_SEP.join([dirp, VIRUS_DIR]), self.virusscanner.get_user_data_path())

						print("Virus file removed: " + str(self.virusscanner.virus_files))

					elif enable_usbbasicvirus_scan:
						usb_autorun_basicvirus_remover(os.path.normpath(OS_DIR_SEP.join([dirp,file])), self.virus_not_removed_list)

			if dirs == []: return
			for dir_ in dirs:
				self.scan_all_dirs(os.path.join(root, dir_))



def main(argv):
	if len(argv) > 1:
		var_path = ""
		var_scantype = ""

		try:
			opts, args = getopt.getopt(argv[1:], "rhp:s:w:o:",["registry", "help", "path=", "scantype=", "threadwait=", "oslatency="])
		except getopt.GetoptError:
			print("%s" % (" ".join([argv[0], "[-rhpswo]"])))
			sys.exit(20)

		for opt, arg in opts:
			if opt in ("-h", "--help"):
				print(""" 
Usage: shortcut_virus_remover.py [-h] [-p path] [-s type] [-w] [-o] [-r]
--help,     -h                         :Print this help message and exit.
--path,     -p <directory>             :Specify the directory to scan.
--scantype, -s [shallow|deep|realtime] :Specify the type of scanning to perform.
                              shallow  :only scan the toplevel of the specified 
                                        directory.
                              deep     :Scan the toplevel and all subdirectory 
                                        of the specified directory.
                              realtime :This mode scan drives automatically and
                                        in realtime. 
--registry, -r                         :Remove and change virus configuration 
                                        keys and values in windows registry. 
                                        Enables certian critical system programs
                                        disabled by the virus.[WINDOWS ONLY]

Configuration Options:
--threadwait -w <wait in seconds>     :The amount of time the spawned threads 
                                       are supposed to wait before the next 
                                       scan for the realtime mode.

--oslatency  -o <period in seconds>   :This defines the latency or delay of the 
                                       OS in setting up certian datastructures.
                                       It improves the responsiveness of the  
                                       application to events like insertion and 
                                       removal of usb devices.
                                        
Your can also run shortcut_virus_remover.py without any option. This will put
you in an interactive mode and it will allow you to set all the required 
parameters.
				""")
			elif opt in ("-w", "--threadwait"):
				global THREAD_WAIT_PERIOD
				THREAD_WAIT_PERIOD = float( (float(arg) > 0 and arg or THREAD_WAIT_PERIOD) )

			elif opt in ("-o", "--oslatency"):
				global RATE_OF_DETECTION
				RATE_OF_DETECTION = float( (float(arg) > 0 and arg or RATE_OF_DETECTION) )

			elif opt in ("-p", "--path"):
				if not validate_dir_path(arg):
					#os_type = platform.system()

					if os_type == 'Linux':
						print(r"ERROR:The directory format is wrong [Note:/home/other_dir]")
						sys.exit(21)
					elif os_type == 'Windows':
						print(r"ERROR:The directory format is wrong [Note:C:\Users\other_dir")
						sys.exit(21)

				if not os.path.exists(arg):
					print(r"ERROR:Specified path does not exist")
					sys.exit(22)
				else:
					var_path = os.path.normpath(arg)

			elif opt in ("-s", "--scantype"):
				if not arg.lower() in ("shallow", "deep", "realtime"):
					print(r"ERROR:Scan type can only be [shallow|deep|realtime]!!!")
					sys.exit(23)
				else:
					var_scantype = arg.lower()

			elif opt in ("-r", "--registry"):
				if os_type == "Windows":
					enable_windows_system_softwares()


		if var_scantype:
			if var_scantype == "deep":                         #### Deep scanning of drives
				deep_scanner = DeepVirusScanner()
				deep_scanner.scan_all_dirs(var_path, enable_usbbasicvirus_scan=True)
			
			elif var_scantype == "shallow":                    #### Shallow scanning of drives
				shallow_scanner = VirusScanner()
				shallow_scanner.check_for_virus(var_path)
			
			else:																#### Realtime scanning mode
				drive = read_partitions()

				realtime_scanner = USBDeviceDetectionAndProtection(len(drive), drive)
				#try:
				realtime_scanner.poll_on_usbdevices(5)
				#except:
				#	print("[%d]: %s" % (PID, "Exiting real scanning mode ..."))

			return

	else: 																	### Interactive scanning
		prompt = str(input("\n\nDo you want a deep scanning of your device[y[N]]? "))
		if not prompt == "" and prompt.upper()[0] == "Y":
			deep_scanner = DeepVirusScanner()
			var = ""

			while True:
				var=str(input("Enter the path to the directory you want to scan\n[[ENTER] for current directory]: "))
				if validate_dir_path(var): break

			if not var == "": deep_scanner.scan_all_dirs(os.path.normpath(var), enable_usbbasicvirus_scan=True)
			else: deep_scanner.scan_all_dirs(enable_usbbasicvirus_scan=True)
		else:
			#shallow scanning or scan the top level of the current working directory
			virus_scanner = VirusScanner()

			if virus_scanner.check_is_affected():
				print("\n\nDRIVE INFECTED WITH SHORTCUT VIRUS!!!")
				time.sleep(1)

				print("\n[%d]:%s" % (PID, "Removing shortcuts ..."))
				for entry in glob.glob("*.lnk"):
					os.remove(entry)

				print("[%d]:%s" % (PID, " ".join(["Removing ", virus_scanner.get_batch_file_path(), " ..."])))
				os.remove(virus_scanner.batch_file_path)
				time.sleep(DELAY)

				print("[%d]:%s" % (PID, "Creating folder " + virus_scanner.user_data_dir + "..."))
				if not os.path.exists(virus_scanner.user_data_dir):
					os.makedirs(virus_scanner.user_data_dir)
				time.sleep(DELAY)
				print("[%d]:%s" % (PID, "Your recovered files will be saved at " + virus_scanner.user_data_dir + "..."))
				time.sleep(DELAY)

				virus_scanner.check_for_virus()

				if os.path.exists(OS_DIR_SEP.join([virus_scanner.get_root_path(), VIRUS_DIR])):
					shutil.rmtree(OS_DIR_SEP.join([virus_scanner.get_root_path(), VIRUS_DIR]), ignore_errors=True)

				print("Virus file removed: " + str(virus_scanner.virus_files))
			else:
				print("\n\nDRIVE NOT INFECTED")

	input("Press Enter to exit")
	return

if __name__ == '__main__':
	try:
		print(info_b.decode("utf-32"))
	except:
		pass
	main(sys.argv)
	sys.exit(0)
