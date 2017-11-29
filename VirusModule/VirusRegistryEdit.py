#!/usr/bin/env python

import os
import imp
import re 

OS_DIR_SEP = os.sep

IsVirus = True
notVirus = False

virus_info_dict = { "ravmon.exe":[[isVirus, "C:\Windows", "C:\Windows\System32"], [], OS_DIR_SEP.join(["virus_signatures", "ravmon.py"]), None], 
                    "ntdelect.com":[[notVirus], [], OS_DIR_SEP.join(["virus_signatures", "ntdelect.py"]), None], 
                    "new folder.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "kavo.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "autorun.inf":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "newfolder.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "scvvhsot.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "scvvhsot.py"]), None], 
                    "scvhsot.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "scvhsot.py"]), None], 
                    "hinhem.scr":[[], [], OS_DIR_SEP.join(["virus_signatures", "hinhem.py"]), None], 
                    "scvhosts.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "scvhosts.py"]), None],
                    "new_folder.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "regsvr.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "regsvr.py"]), None], 
                    "svichossst.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "svichossst.py"]), None], 
                    "autorun.ini":[[], [], OS_DIR_SEP.join(["virus_signatures", "new_folder.py"]), None], 
                    "blastclnnn.exe":[[], [], OS_DIR_SEP.join(["virus_signatures", "blastclnnn.py"]), None],
                    "csrss.exe":[[notVirus, "C:Windows\System32"], [], OS_DIR_SEP.join(["virus_signatures", "csrss.py"]), None]
                    "Drive.bat":[[isVirus r'\D:Drive.bat',r'\D:Drive\' ], [], OS_DIR_SEP.join["virus_signatures", "drive_bat.py"], None]
                  }  #"arona.exe", "logon.bat"

class VirusRegistryEditing:
	''' Registry editting functionals for various viruses '''
	
	def __init__(self):
		self.virus_name = None    #Name of the virus binary without the directory path
		self.virus_location = None    #path to the virus binary with the directory path
		self.original_binary = []   #some viruses takes the names of important system binaries.
		                                #However, the are located in different directories from this
		
		self.other_virus_data = []  #Some virus datum
		self.module_name = None  #Name of module to load
		self.registry_editing_func = None  #Name of function that does the registry editing for this virus
		
		self.loaded_module_Obj = None  #Module object for imports
	
	
	def set_virus_name(self, name):
		self.virus_name = name
		
	def set_virus_path(self, ppath):
		self.virus_location = ppath
		
	def get_virus_name(self):
		return self.virus_name
		
	def get_virus_location(self):
		return os.path.normpath(self.virus_location)
		
	def set_params(self):
		vname = self.get_virus_name()
		
		self.original_binary = virus_info_dict[vname][0]
		self.other_virus_data = virus_info_dict[vname][1]
		self.module_name = virus_info_dict[vname][2]
		self.registry_editing_func = virus_info_dict[3]
		
	def load_module(self):
		if self.module_name is None:
			raise ValueError("module name not set")
		
		mpath, mname = os.path.split(self.module_name)
		mname_no_ext, mext = os.path.splitext(mname)
		
		module_name_noext = os.path.join([mpath, mname_no_ext])
		if os.path.exists( ".".join([module_name_noext, 'pyc'])) ):
			self.loaded_module_Obj = imp.load_compiled(mname_no_ext, module_name_noext + '.pyc')
		
		elif os.path.exists( ".".join([mname_no_ext, "py"]) ):
			self.loaded_module_Obj = imp.load_source(mname_no_ext, module_name_noext + '.py')
		
	def registry_edit_func(self):
		if self.loaded_module_Obj is None:
			raise ValueError("Objetc not set")
		elif self.registry_editing_func is None:
			raise ValueError("Registry editing function not set")
			
		if hasattr(self.loaded_module_Obj, self.registry_editing_func):
			getattr(self.loaded_module_Obj, self.registry_editing_func)()
		else:
			raise AttributeError("Object does not have attribute %s" % self.registry_editing_func)
		
	def run_original(self):
		if self.original_binary is None
			return
