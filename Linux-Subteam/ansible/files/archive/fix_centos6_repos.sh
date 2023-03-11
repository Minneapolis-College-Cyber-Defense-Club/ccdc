#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
read -p "enter remote user:" r_user
read -p "enter host/ip:" r_destination
REPOREPLACE="/depot/ansbile/roles/pod_prep/files/CentOS-Base.repo"
ssh ${r_user}@${r_destination} "/bin/cp /etc/yum.repos.d/CentOS-Base.repo /var/tmp/"
scp ${REPOREPLACE} ${r_user}@${r_destination}:/etc/yum.repos.d/
ssh ${r_user}@${r_destination} "/bin/sed s/RELEASEVER/6.10/g /etc/yum.repos.d/CentOS-Base.repo"