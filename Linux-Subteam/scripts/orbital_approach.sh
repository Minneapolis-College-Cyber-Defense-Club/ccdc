#!/bin/bash
###
# orbital approach
# meant to be first run before all others
###
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
# global vars
DNS="1.1.1.1"
HOSTNAME="$(uname -n)"
IP="127.0.0.1"
DEPOT="/depot"
OS=$(grep '^ID=' /etc/os-release | awk -F= '{print $2}' | tr -d [:punct:])
OS_VER="$(grep '^VERISON_ID=' /etc/os-release | awk -F\" '{print $2}')"
#GITHOLE="https://github.com/Minneapolis-College-Cyber-Defense-Club/Linux-Subteam.git"
URL_BASE="https://raw.githubusercontent.com/Minneapolis-College-Cyber-Defense-Club/Linux-Subteam/main"
SCR_BASE="${DEPOT}/scripts"
PB_BASE="${DEPOT}/ansible/playbooks"
COLLECTIONS="ansible.posix community.general"
NOLOGIN="$(which nologin)"


# initial checks
if [[ $(/usr/bin/whoami) != 'root' ]]; then   
    printf "Must run as root.\n"
    exit 666
fi

# basic networking fixes to clean up some noted concerns on 
# Netlab hosts
cp /etc/resolv.conf /etc/resolv.conf.orig
# critical we don't have a poisoned DNS 
printf "checking dns...\n"
grep "${DNS}" /etc/resolv.conf 
case $? in
    0) 
        printf "Looks correct.\n" 
        ;;
    *) 
        printf "nameserver ${DNS} \n">/etc/resolv.conf
        ;;
esac
printf "checking /etc/hosts...\n"
mv /etc/hosts /etc/hosts.orig
printf "\n">/etc/hosts
# in case there is more than 1 interface
for i in $(ifconfig | cut -f1 -d: | grep '^[a-z]' | grep -v lo)
do
    printf "$(ifconfig ${i} |grep inet | grep -v inet6 | awk '{print $2}') $(uname -n | cut -f1 -d.) $(uname -n)\n">>/etc/hosts
done

# install pre-reqs
printf "installing requirements...\n"
# install required packages
case ${OS} in
    centos | rocky | redhat) PKG="yum" 
        ${PKG} clean all
        ${PKG} makecache
        ${PKG} install -y epel-release libselinux-python
        PYTHON=python
    ;;
    ubuntu) PKG="apt"
        # echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main">>/etc/apt/sources.list
        # apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367
        ${PKG} install -y software-properties-common
        apt-add-repository -y ppa:ansible/ansible
        ${PKG} update
        ${PKG} install -y python-crypto python python3
        PYTHON=python3
    ;;
esac
[[ -x /usr/bin/python ]] || ${PKG} install -y python
[[ -x /usr/bin/ansible ]] || ${PKG} install -y ansible
[[ -x /usr/bin/tmux ]] || ${PKG} install -y tmux
[[ -x /usr/bin/wget ]] || ${PKG} install -y wget
[[ -x /usr/bin/git ]] || ${PKG} install -y git

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

printf "open the pod bay doors HAL...\n"
for u in hal9000 dave2001 root
do
    printf "enter password for ${u}: \n"
    h_password="$(${PYTHON} -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(),crypt.METHOD_SHA512))')"
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
            read -p "repeat password for ${u} for sudo: " s_password
            echo "ansible_become_password: ${s_password}" > ${DEPOT}/vault/sudo.yml
            ;;
        root)
            USERID="0"
            ;;
    esac
    printf "orcman: ${u}\norcman_id: ${USERID}\n" >> ${USERVAULT}
done

printf "populating the structure...\n"
# pull the things
loopit="true"
while [[ "${loopit}" = "true" ]]
do
# only answer 'n' in our testing environment which will not be available at competition
read -p "At competition? y/n " response
case ${response} in
    y | Y | yes | Yes | YES) GITHOLE="https://github.com/Minneapolis-College-Cyber-Defense-Club/ccdc.git" 
        loopit="false";;
    n | N | no | No | NO) GITHOLE="https://github.com/Minneapolis-College-Cyber-Defense-Club/Linux-Subteam.git"
        loopit="false" ;;
    *) printf "please enter 'y' or 'n' \n" ;;
esac
done 
git clone ${GITHOLE}
# find our repo
REPOLOC="$(find ${HOME} -name Linux-Subteam -type d -print)"
for t in ansible scripts
do
    rsync -av ${REPOLOC}/${t} ${DEPOT}/
done

# pull the required addtiional collections
ansible-galaxy collection install ${COLLECTIONS}

ansible-playbook -i ${DEPOT}/ansible/netlab -l discovery ${PB_BASE}/parking_orbit.yml

printf "!!!Note!!! Run this next, and if inventory needs to be adjuted post-run, as root, run this on discovery:\n
        ansible-playbook -i ${DEPOT}/ansible/netlab -l discovery ${PB_BASE}/add_inv_to_hosts.yml\n"

# pull the collections for hal
su -c "ansible-galaxy collection install ${COLLECTIONS}" hal9000
printf "Host *\n  StrictHostKeyChecking no\n"> /home/hal9000/.ssh/config ; chown hal9000: /home/hal9000/.ssh/config
