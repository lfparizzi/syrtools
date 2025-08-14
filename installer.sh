#!/bin/bash

# Atualiza os repositórios
sudo apt update -y

# Instala ADENUM
sudo apt-get install libsasl2-dev python2-dev libldap2-dev libssl-dev -y
pip3 install pwn==1.0 --break-system-packages
pip3 install python-ldap==3.4.0 --break-system-packages

# Instala o Feroxbuster
sudo apt install feroxbuster -y

# Instala o GAU
tar xvf /programas/gau_2.2.4_linux_amd64.tar.gz
mv /programas/gau /usr/bin/gau

# Mostra a versão instalada
echo "done"
