#!/usr/bin/env bash
## DESCRIPTION: Initial configuration for Ubuntu Server 18.04
## AUTHOR: Florian Hübner (fhuebner@posteo.de)
## URL: https://github.com/huebnerf/ubuntu-setup


# User will be created if not existing
export SETUP_USER='' # <- add username here

# If no key is supplied, user password will be set at runtime and ssh password login will be activated
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
  echo " → Please supply a username at SETUP_USER!"
  exit;
fi

if [ -z "$SETUP_SSHKEY" ];
then
  echo " → NO SSH KEY SUPPLIED, PASSWORD LOGIN WILL BE ENABLED!"
fi

export DEBIAN_FRONTEND=noninteractive


# setup admin user
if id "$SETUP_USER";
then
  echo " → User $SETUP_USER already exists"
else
  echo " → Adding user $SETUP_USER"
  adduser --quiet --disabled-password --gecos "" "$SETUP_USER"
  gpasswd -a "$SETUP_USER" sudo
  if [ -z "$SETUP_SSHKEY" ];
  then
  echo " → Plase specify a password for $SETUP_USER"
    passwd "$SETUP_USER"
  fi
fi


# use default apt archive servers
echo " → Configuring default apt server"
{
  echo "deb http://archive.ubuntu.com/ubuntu bionic main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-updates main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-security main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-backports main restricted universe multiverse"
} > /etc/apt/sources.list
apt-get -qy update


# remove bloat
echo " → Removing bloat"
apt-get -qy autoremove --purge cloud-init landscape-common pastebinit popularity-contest snapd
# cloud-init
echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
# snapd
rm -rf /var/cache/snapd/
rm -rf /root/snap


# update apt packages
echo " → Updating apt packages"
apt-get -qy upgrade


# set up locales
echo " → Configuring locales"
apt-get -qy install language-pack-en-base
timedatectl set-timezone Europe/Berlin
export LC_ALL='en_US.UTF-8'
export LANG='en_US.UTF-8'
update-locale LC_ALL="en_GB.UTF-8" LANG="en_GB.UTF-8"


# install additional apt packages
echo " → Installing additional apt packages"
apt-get -qy install  apt-utils              \
                     autoconf               \
                     automake               \
                     build-essential        \
                     checkinstall           \
                     clang                  \
                     curl                   \
                     fail2ban               \
                     git                    \
                     gnupg2                 \
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
                     tldr                   \
                     tree                   \
                     ufw                    \
                     unzip                  \
                     wget


# clean up apt
echo " → Cleaning up apt"
apt-get -qy clean
apt-get -qy autoremove


# ssh config
echo " → Configuring ssh"
{
  echo "HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256"
  echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
  echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"
  echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  echo "HashKnownHosts yes"
} > /etc/ssh/ssh_config


# sshd config
echo " → Configuring sshd"
{
  echo "HostKey /etc/ssh/ssh_host_ed25519_key"
  echo "HostKey /etc/ssh/ssh_host_rsa_key"
  echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
  echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
  echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
  echo "LogLevel VERBOSE"
  echo "Subsystem sftp  /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO"
  echo "PermitRootLogin No"
  echo "LoginGraceTime 1m"
  echo "UseDNS no"
  echo "AllowTcpForwarding no"
  echo "X11Forwarding no"
  echo "AuthenticationMethods publickey"
  echo "UsePAM yes"
  echo "PasswordAuthentication no"
  echo "PermitEmptyPasswords no"
  echo "ChallengeResponseAuthentication no"
  echo "KerberosAuthentication no"
  echo "GSSAPIAuthentication no"
  echo "Match User $SETUP_USER"
  echo "    AllowTcpForwarding yes"
} > /etc/ssh/sshd_config


# configure ssh auth
if [[ -n "$SETUP_SSHKEY" ]];
then
  echo " → Authorizing ssh key"
  cd /home/"$SETUP_USER"
  mkdir -p .ssh
  touch .ssh/authorized_keys .ssh/known_hosts
  echo "$SETUP_SSHKEY" > .ssh/authorized_keys
  chmod 700 .ssh
  chmod 600 .ssh/authorized_keys
  chown -R "$SETUP_USER":"$SETUP_USER" .ssh
else
  echo " → Enabling ssh password auth for $SETUP_USER"
  {
    echo "    AuthenticationMethods publickey password"
    echo "    PasswordAuthentication yes"
  } >> /etc/ssh/sshd_config
fi


# generate server keys
echo " → Deleting old ssh server keys"
cd /etc/ssh
shred -u ssh_host_*key*
echo " → Generating ed25519 ssh server key"
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ''
echo " → Generating rsa ssh server key"
ssh-keygen -t rsa -b 8192 -f ssh_host_rsa_key -N ''


# restart sshd
echo " → Restarting sshd"
systemctl restart sshd


# configure firewall
echo " → Setting up firewall"
ufw logging on
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh/tcp
ufw --force enable
