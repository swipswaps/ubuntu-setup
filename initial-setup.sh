#!/usr/bin/env bash
## DESCRIPTION: Initial configuration for Ubuntu Server 18.04
## AUTHOR: Florian Hübner (fhuebner@posteo.de)
## URL: https://github.com/huebnerf/ubuntu-setup

export SETUP_USER='' # <- add username here
export SETUP_SSHKEY='' # <- add ssh pubkey here

########

set -e

if [ "$EUID" -ne 0 ]
then
  echo " → Please run this script with sudo or as root!"
  exit
fi


if ! grep -q DISTRIB_CODENAME=bionic /etc/lsb-release;
then
  echo " → This script is intended to be run on Ubuntu 18.04 LTS Bionic Beaver!";
  exit;
fi


if [ -z "$SETUP_USER" ];
then
  echo " → Please supply a Username at SETUP_USER!"
  exit;
fi


if [ -z "$SETUP_SSHKEY" ];
then
  echo " → NO SSH KEY SUPPLIED, PASSWORD LOGIN WILL BE ENABLED!"
fi


export DEBIAN_FRONTEND=noninteractive


# setup user
if id "$SETUP_USER" >/dev/null 2>&1;
then
  echo " → user already exists"
else
  echo " → adding user"
  adduser --quiet --disabled-password --gecos "" "$SETUP_USER"
  gpasswd -a "$SETUP_USER" sudo
fi


# use default apt archive servers
echo " → configuring default apt server"
{
  echo "deb http://archive.ubuntu.com/ubuntu bionic main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-updates main restricted universe multierse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-security main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-backports main restricted universe multiverse"
} > /etc/apt/sources.list


# remove bloat
echo " → removing bloat"
apt-get -qy autoremove --purge cloud-init snapd
# cloud-init
echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
# snapd
rm -rf /var/cache/snapd/
rm -rf /root/snap


# update packages
echo " → updating apt packages"
apt-get -qy update
apt-get -qy upgrade


# set up locales
echo " → configuring locales"
apt-get -qy install language-pack-en-base
timedatectl set-timezone Europe/Berlin
export LC_ALL='en_US.UTF-8'
export LANG='en_US.UTF-8'
update-locale LC_ALL="en_GB.UTF-8" LANG="en_GB.UTF-8"


# install packages
echo " → installing additional apt packages"
apt-get -qy install  apt-utils              \
                     autoconf               \
                     automake               \
                     build-essential        \
                     checkinstall           \
                     clang                  \
                     curl                   \
                     fail2ban               \
                     git                    \
                     gnuplot                \
                     htop                   \
                     iftop                  \
                     make                   \
                     man                    \
                     nano                   \
                     netcat                 \
                     openssh-server         \
                     rsync                  \
                     screen                 \
                     shellcheck             \
                     sudo                   \
                     tldr                   \
                     tree                   \
                     ufw                    \
                     unzip                  \
                     wget


# clean up
echo " → cleanup apt"
apt-get -qy clean
apt-get -qy autoremove


# ssh config
echo " → configuring ssh"
cat <<'EOF' > /etc/ssh/ssh_config
HashKnownHosts yes
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF


# sshd config
echo " → configuring sshd"
cat <<'EOF' > /etc/ssh/sshd_config
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

AuthenticationMethods publickey
PermitRootLogin No
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
EOF


# configure ssh auth
if [[ -n "$SETUP_SSHKEY" ]];
then
  echo " → authorizing ssh key"
  cd /home/"$SETUP_USER"
  mkdir -p .ssh
  touch .ssh/authorized_keys .ssh/known_hosts
  echo "'$SETUP_SSHKEY'" > .ssh/authorized_keys
  chmod 700 .ssh
  chmod 600 .ssh/authorized_keys
  chown -R "$SETUP_USER":"$SETUP_USER" .ssh
else
  echo " → ENABLING SSH PASSWORD AUTH!"
  sed -i "/AuthenticationMethods/s/publickey/publickey password/g" /etc/ssh/sshd_config
fi


# generate server keys
echo " → generating ssh server keys"
cd /etc/ssh
shred -u ssh_host_*key*
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ''
ssh-keygen -t rsa -b 8192 -f ssh_host_rsa_key -N ''


# restart sshd
echo " → restarting sshd"
systemctl restart sshd


# configure firewall
echo " → configuring firewall"
ufw logging on
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh/tcp
ufw --force enable
