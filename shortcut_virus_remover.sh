#!/bin/bash

#Wed 15 Nov 2017 12:48:29 AM GMT 

#===========================================================================================
# Copyright (C) 2017 Nafiu Shaibu.
# Purpose: Short cut virus removal and files recovery
#-------------------------------------------------------------------------------------------
# This is free software; you can redistribute it and/or modify it
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

VIRUS_DIR="Drive"
VIRUS_FILE="Drive.bat"
DIR_TO_SCAN=${PWD}
USER_DATA_DIR="${DIR_TO_SCAN}/Your_files_$$"
DELAY=0.2

batch_file=""
declare -a virus_dir=()

function isdigit(){
	if [ -z "$1" ]; then
		return 	$FAILURE
	fi 
	
	case "$1" in 
		[[:digit:]]|[[:digit:]]*) return 0 ;;
		*)	return 1 ;;
	esac
}

function move_user_data() {
	mv $1 ${USER_DATA_DIR} 2>&1 1>/dev/null
}

function check_is_affected() {
	local bool=1
	batch_file=$(find ${DIR_TO_SCAN} -type f -a -name ${VIRUS_FILE} -print 2>/dev/null)
	[ "`basename ${batch_file#*/} 2>/dev/null`" = "${VIRUS_FILE}" ] && { bool=0; }
	
	return ${bool}
}

function check_is_virus() {
	let "i=0"
	
	[ -d $1 ] && [ "$(basename $1 2>&1 1>/dev/null)"=${VIRUS_DIR} ] && { 
		for entry in $(find ${VIRUS_DIR} -maxdepth 1 -print 2>/dev/null); do 
			
			if isdigit $(basename ${entry} 2>/dev/null) && [ -d $1/${entry} ]; then
				tput setaf 9
				echo "checking $(basename ${entry} 2>>/dev/null) ..."
				tput sgr0
				javascript_file=$(find "$1/$entry" -type f -a -name *.js -print 2>/dev/null)
				
				if [ "${javascript_file}" != "" ]; then
					virus_dir[ $(( i++ )) ]=${entry} 
					rm -rf "$1/${entry}" 2>&1 1>/dev/null
					javascript_file=""
				else
					printf "[$$]:%s\n" "Retrieving $(basename $entry) to ${USER_DATA_DIR}"
					move_user_data "$1/${entry}"
				fi 
			else
				[ "$(basename $entry 2>/dev/null)" != "${VIRUS_DIR}" ] && { 
					printf "[$$]:%s\n" "Retrieving $(basename $entry 2>/dev/null) to ${USER_DATA_DIR}"
					move_user_data "$1/${entry}"
				}
			fi 
		done
	}
}

if check_is_affected; then
	printf "%s\n\n" "Copyright (C) 2017 github.com/nshaibu"
	
	tput setaf 9
	echo "Drive infected with shortcut virus!!!"
	tput sgr0
	sleep 1
	
	printf "\n[%d]:%s\n" $$ "Removing shortcuts ..." && sleep ${DELAY}
	rm -f *.lnk 2>&1 1>/dev/null
	printf "[%d]:%s\n" $$ "Removing ${batch_file} ..." && sleep ${DELAY}
	rm -f ${batch_file} 2>&1 1>/dev/null
	printf "[%d]:%s\n" $$ "Creating folder ${USER_DATA_DIR} ..." && sleep ${DELAY}
	[ ! -d ${USER_DATA_DIR} ] && mkdir ${USER_DATA_DIR} 2>&1 1>/dev/null
	printf "[%d]:%s\n" $$ "Your recovered files will be saved at ${USER_DATA_DIR} ..." && sleep ${DELAY}
	
	check_is_virus ${DIR_TO_SCAN} 
	rm -rf "${DIR_TO_SCAN}/${VIRUS_DIR}" 2>/dev/null
	
	echo "Virus folder removed: ${virus_dir[@]}"
else
	tput setaf 6
	echo "Drive not infected" 
	tput sgr0
fi 

exit 0
