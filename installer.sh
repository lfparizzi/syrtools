
#!/bin/bash

# Atualiza os repositórios
sudo apt update -y

# Executando ações comuns
gunzip /usr/share/wordlists/rockyou.txt.gz

# Habilita scripts
chmod +x NetworkScanner.sh

# Instala ADENUM
sudo apt-get install libsasl2-dev python2-dev libldap2-dev libssl-dev -y
pip3 install pwn==1.0 --break-system-packages
pip3 install python-ldap==3.4.0 --break-system-packages
echo ""
echo "FIM DA INSTALAÇÃO DO ADENUM"


# Instala o Feroxbuster
sudo apt install feroxbuster -y
echo ""
echo "FIM DA INSTALAÇÃO DO FEROXBUSTER"


# Instala o GAU
tar xvf programas/gau_2.2.4_linux_amd64.tar.gz -C programas/
mv programas/gau /usr/bin/gau
echo ""
echo "FIM DA INSTALAÇÃO DO GAU"

#fim
echo "░▀█▀░█▀█░█▀▀░▀█▀░█▀█░█░░░█░░░█▀▀░█▀▄░░░█▀▄░█▀█░█▀█░█▀▀
░░█░░█░█░▀▀█░░█░░█▀█░█░░░█░░░█▀▀░█▀▄░░░█░█░█░█░█░█░█▀▀
░▀▀▀░▀░▀░▀▀▀░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░░░▀▀░░▀▀▀░▀░▀░▀▀▀"

