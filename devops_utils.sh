TPUT=/usr/bin/tput
RED=$($TPUT setaf 1)
GREEN=$($TPUT setaf 2)
YELLOW=$($TPUT setaf 3)
NORMAL=$($TPUT op)

BOLD=$(${TPUT} bold)
UNDERLINE=$(${TPUT} smul)
RM_UNDERLINE=$(${TPUT} rmul)
RM_ATTRS=$(${TPUT} sgr0)

setx=green_echo
#==============================
green_echo ()
#==============================
{
        echo -ne "\n${GREEN}$@${RM_ATTRS}\n\n"
} #green_echo

setx=red_echo
#==============================
red_echo ()
#==============================
{
        echo -ne "\n${RED}$@${RM_ATTRS}\n\n"
} #red_echo
