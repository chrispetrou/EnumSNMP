#!/bin/bash

NC='\033[0m'
UN='\033[4m'
BG='\033[1;32m'
FR='\033[1;31m'
YL='\033[1;33m'
WH='\033[1;37m'

echo -e "${WH}┌═════════════════════════┐"
echo -e "${WH}│ SNMP enumeration script │"
echo -e "${WH}└═════════════════════════┘"

if [ $# -lt 2 ]; then
    echo -e "--------------------------------------------------------"
    echo -e "${WH}[*]${NC} SNMP enumeration script"
    echo -e "${WH}[*]${NC} Usage: $0 <ip> <SNMPversion> <comms_file>"
    echo -e "════════════════════════════════════════════════════════"
    echo -e "\n${WH}[!] ip:${NC} the target-ip."
    echo -e "${WH}[!] SNMPversion:${NC} can be either v1 or v2c."
    echo -e "${WH}[!] comms_file:${NC} file containing communities - it's optional."
    exit 0
fi

unquote() {
    sed "s/^\(\"\)\(.*\)\1\$/\2/g" <<<$1
}

trim() {
    sed 's/^[[:space:]]*//g' <<<$1
}

if [ ! -z "$3" ]; then
    # if communities file is specified
    comms=()
    for cm in $(cat $3); do
        comms+=("$cm")
    done
else
    # some default-to-check communities 
    # if a communities-file is not specified.
    declare -a comms=("public" "private" "manager")
fi

# now loop and check for communities
echo -e ''
exists=()
for comm in "${comms[@]}";do
    i=0;
    echo -ne "\r${BG}[+]${NC} ${WH}Checking for ${BG}$comm${NC} ${WH}community:${NC} "
    result=$(onesixtyone $1 $comm | grep "$1")
    if [ ! -z "$result" ]; then
        exists+=("$comm")
        echo $result
    else
        echo -e "${FR}Not found!${NC}"
    fi
done

# enumerate further if communities found...
if [ ! -z "$exists" ]; then
    for comm in "${exists[@]}";do
        echo -e "${YL}\n[+]${NC}${WH} ${UN}Enumerating user accounts based on $comm community:${NC}\n"
        snmpwalk -c $comm -$2 $1 1.3.6.1.4.1.77.1.2.25 | while read line ; do
            unquote "$(trim $(echo -e $line | cut -d ':' -f2))"
        done

        procnum=$(unquote "$(trim $(echo -e $(snmpwalk -c $comm -$2 $1 1.3.6.1.2.1.25.1.6.0) | cut -d ':' -f2))")
        echo -e "${YL}\n[+]${NC}${WH} ${UN}Enumerating running processes based on $comm community:${NC}\n"
        echo -e "${UN}${BG}$procnum${NC}${UN} running processes found:${NC}"
        snmpwalk -c $comm -$2 $1 1.3.6.1.2.1.25.4.2.1.2 | while read line ; do
            unquote "$(trim "$(echo -e $line | cut -d ':' -f2)")"
        done

        echo -e "${YL}\n[+]${NC}${WH} ${UN}Enumerating TCP local ports based on $comm community:${NC}\n"
        snmpwalk -c $comm -$2 $1 1.3.6.1.2.1.6.13.1.3 | while read line ; do
            port=$(unquote "$(trim $(echo -e $line | cut -d ':' -f2))")
            findservice=$(python -c "print __import__('socket').getservbyport(int($port))" 2>/dev/null)
            if [[ $findservice ]]; then
                service=${BG}$findservice${NC}
            else
                service="${FR}Unknown${NC}"
            fi
            echo -e "Port ${BG}$port${NC}/TCP ($service) found!"
        done

        echo -e "${YL}\n[+]${NC}${WH} ${UN}Enumerating software name based on $comm community:${NC}\n"
        snmpwalk -c $comm -$2 $1 1.3.6.1.2.1.25.6.3.1.2 | while read line ; do
            unquote "$(trim "$(echo -e $line | cut -d ':' -f2)")"
        done
    done
fi
