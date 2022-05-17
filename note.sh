#!/bin/zsh

#Simple notes taking script for tests

#command input while loop

while getopts f:a: flag
do
	case "${flag}" in
		#f) touch note_file_${OPTARG}.txt;;
		a) attack=${OPTARG};;
	esac
done

echo $attack >>note_file.txt;
date >>note_file.txt;
curl ipinfo.io >>note_file.txt;
echo $'\n\n\n' >>note_file.txt;
