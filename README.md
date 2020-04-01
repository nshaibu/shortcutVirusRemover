Copyright (C) 2017 Nafiu Shaibu [github/nshaibu]. 
Wed 15 Nov 2017 12:47:46 AM GMT

# REQUIREMENTS
* python 3				
* pyudev package on linux



# SHORTCUT VIRUS REMOVER
These scripts retrieve user files and folders and remove shortcut virus from USB storage 
drives like pendrives. The signature of the shortcut virus (it removes) is that the virus 
creates a batch script in the folder it affects and converts everything in the folder 
into a shortcut(ie .lnk file). This virus takes the advantage of windows autorun or 
autoplay feature to spread. The virus affects computers when an infected usb storage drive 
is inserted into the computer and the user trys to write or read from it. This means that 
whenever there is either a read or write to the inserted drive the virus script is run. 

So just opening an infected USB storage device using any file manager will get your 
Computer infected because the file manager has to read the various datastructures on 
the USB device to display icons of the files on the drive.


# USAGE
[WARNING] Because of the way the shortcut virus infects computers, it is advisable to 
[WARNING] disable autorun on your windows PC before you inserted the infected USB 
[WARNING] storage(like pendrives). Again, do not open your drive manually on your 
[WARNING] PC until you have scanned it with [shortcut_virus_remover.py].

Note the path to your drive without opening it. Then either click on [shortcut_virus_remover.py]
or start your CMD and then run the [shortcut_virus_remover.py] as show below:
	```
	$CMD_PROMPT> python shortcut_virus_remover.py --path=<path to your drive> --scantype=[deep|shallow|realtime]
	```
							OR
	```						
	$CMD_PROMPT> python shortcut_virus_remover.py -p <path to your drive> -s [shallow|deep|realtime]
	```

If you click on [shortcut_virus_remover.py], it will open a CMD window. Fill in the 
the needed requirements and press [ENTER].

However on linux you can either use shortcut_virus_remover.sh or shortcut_virus_remover.py: 
	```	
	$CMD_PROMPT> sh ./shortcut_virus_remover.sh
	```
				OR
	```			
	$CMD_PROMPT> python ./shortcut_virus_remover.py
	```

	
## DEEP SCANNER 
For the deep scanner, it is only implemented for shortcut_virus_remover.py script:
It can be run from any directory and it scans through all the subdirectories of the
toplevel directory to search and remove the viruses and also recover user files:


# REALTIME SCANNER 
The realtime scanner is implemented only for the python script. When the script is
runned, it waits till when the user inserts a usb device. It then determine the 
partitions the usb device have and creates threads to clean each partition off the
autorun viruses. It then waits for some configurable number of seconds and do a shallow
scanner of the partitions.

[NOTE]: The realtime mode protects computers from getting infected by the shortcut virus.
[NOTE]: So when you login into a PC open the CMD and run the command below so that whenever
[NOTE]: you or someone insert usb storage device, it checks and remove the virus before
[NOTE]: it can affect the PC too.
	```
	$CMD_PROMPT> python ./shortcut_virus_remover.py --scantype=realtime
	```
	
Now realtime scanning on microsoft windows is working

For help on the various option refer to the help by typing this command at the 
CMD prompt:
	```
	$CMD_PROMPT> shortcut_virus_remover.py --help
	```
