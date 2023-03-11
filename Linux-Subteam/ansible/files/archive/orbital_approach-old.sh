#!/bin/bash

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
# global vars
DNS="1.1.1.1"
HOSTNAME="$(uname -n)"
DEPOT="/depot"
OS="$(grep '^ID=' /etc/os-release | awk -F\" '{print $2}')"
OS_VER="$(grep '^VERISON_ID=' /etc/os-release | awk -F\" '{print $2}')"
GITHOLE="https://github.com/Minneapolis-College-Cyber-Defense-Club/Linux-Subteam.git"
URL_BASE="https://raw.githubusercontent.com/Minneapolis-College-Cyber-Defense-Club/Linux-Subteam/main"
SCR_BASE="${DEPOT}/scripts"
PB_BASE="${DEPOT}/ansible/playbooks"
COLLECTIONS="ansible.posix community.mysql community.general"
NOLOGIN="$(which nologin)"

# initial checks
if [[ $(/bin/whoami) != 'root' ]]; then   
    printf "Must run as root.\n"
    exit 666
fi
# changing root's password
read -p "enter new root password: " r_password
echo ${r_password} | passwd root --stdin

# make sure it is setup on the expected OS
[[ ${OS} != centos && ${OS_VER} != 7 ]] || (printf "wrong os detected...bye.\n" ; exit 667)

# lock less tha uid 1024 accounts that aren't root
printf "scanning accounts less than uid 1024...\n"
for u in $(awk -F: '($3 < 1000) {print $1}' /etc/passwd)
do
    if [[ "${u}" != "root" ]]; then
        usermod -L ${u}
    fi
    if [[ "${u}" != "sync"  && "${u}" != "shutdown" && "${u}" != "halt" && "${u}" != "root" ]]; then
        usermod -s ${NOLOGIN} ${u}
    fi
done

# create the depot
printf "generating depot structure..."
for d in vault keys files quarantine
do
    mkdir -p ${DEPOT}/${d}
done
chown -R root: ${DEPOT}
chmod 700 ${DEPOT}

printf "building quarantine..."
# build file quarantine
QUARANTINE="${DEPOT}/quarantine"
chmod 700 ${QUARANTINE}

# basic security and functionality checks
# at this point /etc/resolv.conf should have been fixed via kill chain BUT VALIDATE
# backup and validate files
cp /etc/resolv.conf ${QUARANTINE}/
# critical we don't have a poisoned DNS 
printf "checking dns...\n"
grep "${DNS}" /etc/resolv.conf 
case $? in
    0) 
        printf "Looks correct.\n" 
        ;;
    *) 
        mv /etc/resolv.conf ${QUARANTINE}/
        printf "nameserver ${DNS} \n">/etc/resolv.conf
        ;;
esac
printf "checking /etc/hosts...\n"
cp -p /etc/hosts ${QUARANTINE}/
mv /etc/hosts /etc/hosts.prev
printf "127.0.0.1 localhost localhost.localdomain\n::1 localhost localhost.localdomain\n">/etc/hosts
# in case there is more than 1 interface
for i in $(ifconfig | cut -f1 -d: | grep '^[a-z]' | grep -v lo)
do
    printf "$(ifconfig ${i} |grep inet | grep -v inet6 | awk '{print $2}') $(uname -n | cut -f1 -d.) $(uname -n)\n">>/etc/hosts
done
printf "saving copies of other files...\n"
cp -p /root/.bash_history ${QUARANTINE}/root.bash_history
cp -p /etc/ssh/sshd_config ${QUARANTINE}/
cp -pr /etc/sudoers* ${QUARANTINE}/

# clean out crontabs
mkdir ${QUARANTINE}/crons
for c in $(ls /var/spool/cron)
do
    mv /var/spool/${c}  ${QUARANTINE}/crons/
    [[ -f /var/spool/${c} ]] && rm -f /var/spool/${c}
done
printf "quarantine content: \n"
ls -la ${QUARANTINE}

printf "installing requirements...\n"
# install required packages
# need EPEL
yum install -y epel-release libselinux-python
[[ -x /bin/python ]] || yum install -y python
[[ -x /bin/ansbile ]] || yum install -y ansible
[[ -x /bin/tmux ]] || yum install -y tmux
[[ -x /bin/wget ]] || yum install -y wget
[[ -x /bin/git ]] || yum install -y git

printf "populating the structure...\n"
# pull the things
for t in ansible scripts
do
    git clone ${GITHOLE}
    cp -r ~/Linux-Subteam/${t} ${DEPOT}/
done
# make it read-only
#chmod 0600 ~/Linux-Subteam

# pull the collections
ansible-galaxy collection install ${COLLECTIONS}

# create things needed
printf "open the pod bay doors HAL...\n"
for u in hal9000 dave2001
do
    printf "enter password for ${u}: \n"
    h_password="$(python -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(),crypt.METHOD_SHA512))')"
    [[ -d ${DEPOT}/vault ]] || mkdir -p ${DEPOT}/vault
    USERVAULT="${DEPOT}/vault/${u}.yml"
    echo "h_password: ${h_password}" > ${USERVAULT}
    # add more to the vault
    case "${u}" in
        hal9000)
            USERID="111111"
            ;;
        dave2001)
            USERID="111112"
            ;;
    esac
    printf "orcman: ${u}\norcman_id: ${USERID}\n" >> ${USERVAULT}
done
ansible-playbook -i localhost, ${PB_BASE}/parking_orbit.yml

# pull the collections
su -c "ansible-galaxy collection install ${COLLECTIONS}" hal9000
