#!/usr/bin/env python

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

VIRUS_DIR = "Drive"
VIRUS_FILE = "Drive.bat"
DELAY = 0.2
OS_DIR_SEP = os.sep

info_b = b'\xff\xfe\x00\x00C\x00\x00\x00o\x00\x00\x00p\x00\x00\x00y\x00\x00\x00r\x00\x00\x00i\x00\x00\x00g\x00\x00\x00h\x00\x00\x00t\x00\x00\x00 \x00\x00\x00(\x00\x00\x00C\x00\x00\x00)\x00\x00\x00 \x00\x00\x002\x00\x00\x000\x00\x00\x001\x00\x00\x007\x00\x00\x00 \x00\x00\x00N\x00\x00\x00a\x00\x00\x00f\x00\x00\x00i\x00\x00\x00u\x00\x00\x00 \x00\x00\x00S\x00\x00\x00h\x00\x00\x00a\x00\x00\x00i\x00\x00\x00b\x00\x00\x00u\x00\x00\x00[\x00\x00\x00g\x00\x00\x00i\x00\x00\x00t\x00\x00\x00h\x00\x00\x00u\x00\x00\x00b\x00\x00\x00.\x00\x00\x00c\x00\x00\x00o\x00\x00\x00m\x00\x00\x00/\x00\x00\x00n\x00\x00\x00s\x00\x00\x00h\x00\x00\x00a\x00\x00\x00i\x00\x00\x00b\x00\x00\x00u\x00\x00\x00]\x00\x00\x00.\x00\x00\x00'


def validate_dir_path(dir_path):
	if dir_path == "":
		return True
	else:
		os_type = platform.system()
		if os_type == "Linux":
			return re.match(r'^/(\D|\d)*', dir_path) != None
		elif os_type == "Windows":
			return re.match(r'^\D:\\(\D|\d)*', dir_path) != None


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

def move_user_data(dataTomove, userdir):
	if not os.path.exists(userdir):
		os.makedirs(userdir)
	try:
		shutil.move(dataTomove, userdir)
	except:
		print("Cannot retrieve : " + dataTomove + "...")

class VirusScanner:
	def __init__(self):
		self.root_path = os.getcwd()
		self.batch_file_path = None
		self.virus_dir = list()
		self.user_data_dir = OS_DIR_SEP.join([str(self.root_path), "YourFiles" + str(os.getpid())])
		
	def set_root_path(self, path):
		if not os.path.isdir(path):
			return False
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
		return self.batch_file_path != None
			
		
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
									self.virus_dir.append(files_in_dir[i])
								i += 1
						else:
							print("[%d]:Retrieving %s" % (os.getpid(), subentry))
							move_user_data(files_name, self.get_user_data_path())
					else:
						print("[%d]:Retrieving %s" % (os.getpid(), subentry))
						move_user_data(files_name, self.get_user_data_path())
				break
						

class DeepVirusScanner:
	def __init__(self):
		self.virusscanner = VirusScanner()

	def scan_all_dirs(self, dirp=os.getcwd()):

		for root, dirs, files in os.walk(os.path.normpath(dirp)):

			if files == []: return
			else:
				print("Checking for virus in " + dirp)
				for file in files:
					if file == VIRUS_FILE or os.path.isdir(os.path.normpath(OS_DIR_SEP.join([dirp, VIRUS_DIR]))):
						self.virusscanner.set_batch_file_path(os.path.normpath(OS_DIR_SEP.join([dirp, VIRUS_FILE])))
						print("[%d]:%s %s" % (os.getpid(), "Virus found at ", self.virusscanner.get_batch_file_path()))
						print("[%d]:%s" % (os.getpid(), "Removing the virus file"))
						try:
							os.remove(self.virusscanner.get_batch_file_path())
						except:
							pass
						time.sleep(DELAY)

						print("[%d]:%s" % (os.getpid(), "Removing shortcuts"))
						p = re.match(r'(\D|\d)*[\\/]+[Dd][Ee][Ss][Kk][Tt][Oo][Pp]$', dirp, re.IGNORECASE)
						if not p:
							for shortcut in glob.glob(OS_DIR_SEP.join([dirp, "*.lnk"])):
								os.remove(os.path.normpath(shortcut))
						time.sleep(DELAY)

						self.virusscanner.set_root_path(os.path.normpath(dirp))
						self.virusscanner.set_user_data_path(OS_DIR_SEP.join([dirp, "YourFiles" + str(os.getpid())]))

						self.virusscanner.check_for_virus(os.path.normpath(dirp))

						virusdir = OS_DIR_SEP.join([dirp, VIRUS_DIR])
						if os.path.exists(virusdir) and not self.virusscanner.virus_dir == []:
							shutil.rmtree(virusdir, ignore_errors=True)

						print("Virus file removed: " + str(self.virusscanner.virus_dir))

			if dirs == []: return
			for dir_ in dirs:
				self.scan_all_dirs(os.path.join(root, dir_))



def main(argv):
	if len(argv) > 1:
		var_path = ""
		var_scantype = ""

		try:
			opts, args = getopt.getopt(argv[1:], "hp:s:",["help", "path=", "scantype="])
		except getopt.GetoptError:
			print("%s" % (" ".join([argv[0], "[-hps]"])))
			sys.exit(20)

		for opt, arg in opts:
			if opt in ("-h", "--help"):
				print(""" 
Usage: shortcut_virus_remover.py [-h] [-p path] [-s type]
--help,     -h                :Print this help message and exit.
--path,     -p <directory>    :Specify the directory to scan.
--scantype, -s [shallow|deep] :Specify the type of scanning to perform.
               shallow        :only scan the toplevel of the specified directory
               deep           :Scan the toplevel and all subdirectory of the 
                               specified directory.

Your can also run shortcut_virus_remover.py without any option. This will put
you in an interractive mode and it will allow you to set all the required 
parameters.
				""")
			elif opt in ("-p", "--path"):
				print(arg)
				if not validate_dir_path(arg):
					os_type = platform.system()
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
				if not arg.lower() in ("shallow", "deep"):
					print(r"ERROR:Scan type can only be [shallow|deep]!!!")
					sys.exit(23)
				else:
					var_scantype = arg.lower()
		if var_scantype:
			if var_scantype == "deep":
				deep_scanner = DeepVirusScanner()
				deep_scanner.scan_all_dirs(var_path)
			else:
				shallow_scanner = VirusScanner()
				shallow_scanner.check_for_virus(var_path)

			return

	else: #Interractive scanning
		prompt = str(input("\n\nDo you want a deep scanning of your device[y[N]]? "))
		if not prompt == "" and prompt.upper()[0] == "Y":
			deep_scanner = DeepVirusScanner()
			var = ""

			while True:
				var=str(input("Enter the path to the directory you want to scan\n[[ENTER] for current directory]: "))
				if validate_dir_path(var): break

			if not var == "": deep_scanner.scan_all_dirs(os.path.normpath(var))
			else: deep_scanner.scan_all_dirs()
		else:
			#shallow scanning or scan the top level of the current working directory
			virus_scanner = VirusScanner()

			if virus_scanner.check_is_affected():
				print("\n\nDRIVE INFECTED WITH SHORTCUT VIRUS!!!")
				time.sleep(1)

				print("\n[%d]:%s" % (os.getpid(), "Removing shortcuts ..."))
				for entry in glob.glob("*.lnk"):
					os.remove(entry)

				print("[%d]:%s" % (os.getpid(), " ".join(["Removing ", virus_scanner.get_batch_file_path(), " ..."])))
				os.remove(virus_scanner.batch_file_path)
				time.sleep(DELAY)

				print("[%d]:%s" % (os.getpid(), "Creating folder " + virus_scanner.user_data_dir + "..."))
				if not os.path.exists(virus_scanner.user_data_dir):
					os.makedirs(virus_scanner.user_data_dir)
				time.sleep(DELAY)
				print("[%d]:%s" % (os.getpid(), "Your recovered files will be saved at " + virus_scanner.user_data_dir + "..."))
				time.sleep(DELAY)

				virus_scanner.check_for_virus()

				if os.path.exists(OS_DIR_SEP.join([virus_scanner.get_root_path(), VIRUS_DIR])):
					shutil.rmtree(OS_DIR_SEP.join([virus_scanner.get_root_path(), VIRUS_DIR]), ignore_errors=True)

				print("Virus file removed: " + str(virus_scanner.virus_dir))
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
