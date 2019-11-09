#!/usr/bin/env bash
## DESCRIPTION: Initial configuration for Ubuntu Server 18.04
## AUTHOR: Florian Hübner (fhuebner@posteo.de)
## URL: https://github.com/huebnerf/ubuntu-setup


# If user with given name does not exist, it will be created and added to sudo group
export SETUP_USER="" # add username here

# If no ssh key is supplied, ssh password login will be activated for $SETUP_USER
export SETUP_SSHKEY="" # add ssh pubkey here

# Disable IPv6
export SETUP_DISABLE_IPV6=true # true / false

# Harden network settings
export SETUP_HARDEN_NETWORK=true # true / false

# Install Docker CE
export SETUP_INSTALL_DOCKER=true # true / false


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


SETUP_REQUIRES_REBOOT=false


if [ "$SETUP_DISABLE_IPV6" = true ];
then
  # Disable IPv6
  echo " → Disabling IPv6"
  echo "/etc/sysctl.d/01-disable-ipv6.conf" > /etc/sysctl.d/01-disable-ipv6.conf
  {
    echo ""
    echo "net.ipv6.conf.all.disable_ipv6=1"
    echo "net.ipv6.conf.default.disable_ipv6=1"
    echo "net.ipv6.conf.lo.disable_ipv6=1"
  } >> /etc/sysctl.conf
  sysctl -p
  SETUP_REQUIRES_REBOOT=true
fi


if [ "$SETUP_HARDEN_NETWORK" = true ];
then
  # Set hardened network settings
  echo " → Setting hardened network settings"
  {
    echo ""
    echo "net.ipv4.conf.default.rp_filter=1"
    echo "net.ipv4.conf.all.rp_filter=1"
    echo "net.ipv4.tcp_syncookies=1"
    echo "net.ipv4.conf.all.accept_redirects=0"
    echo "net.ipv4.conf.all.send_redirects=0"
    echo "net.ipv4.conf.all.accept_source_route=0"
    echo "net.ipv4.conf.all.log_martians=1"
    if [ "$SETUP_DISABLE_IPV6" = false ];
    then
      echo "net.ipv6.conf.all.accept_redirects=0"
      echo "net.ipv6.conf.all.accept_source_route=0"
    fi
  } >> /etc/sysctl.conf
  sysctl -p
fi


# disable motd ads
echo " → Disabling motd ads"
sed -i 's/ENABLED=1/ENABLED=0/g' /etc/default/motd-news
systemctl disable --now motd-news.timer


# use default apt archive servers
echo " → Configuring default apt server"
{
  echo "deb http://archive.ubuntu.com/ubuntu bionic main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-updates main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-security main restricted universe multiverse"
  echo "deb http://archive.ubuntu.com/ubuntu bionic-backports main restricted universe multiverse"
} > /etc/apt/sources.list


# set up locales
export DEBIAN_FRONTEND=noninteractive
apt-get -qy update
echo " → Configuring locales"
apt-get -qy install language-pack-en-base
timedatectl set-timezone Europe/Berlin
export LC_ALL="en_US.UTF-8"
export LANG="en_US.UTF-8"
update-locale LC_ALL="en_GB.UTF-8" LANG="en_GB.UTF-8"


# remove bloat
echo " → Removing bloat"
apt-get -qy purge               \
  apport                        \
  apport-symptoms               \
  cloud-guest-utils             \
  cloud-init                    \
  cloud-initramfs-copymods      \
  cloud-initramfs-dyn-netconf   \
  landscape-common              \
  pastebinit                    \
  popularity-contest            \
  snapd                         \
  telnet
# clean up cloud-init
rm -rf /etc/cloud/
rm -rf /var/lib/cloud/
# clean up snapd
rm -rf /root/snap
rm -rf /var/cache/snapd/


# full-update apt packages
echo " → Updating apt packages"
apt-get -qy full-upgrade


# install additional apt packages
echo " → Installing additional apt packages"
apt-get -qy install             \
  apt-transport-https           \
  apt-utils                     \
  autoconf                      \
  automake                      \
  build-essential               \
  ca-certificates               \
  checkinstall                  \
  clang                         \
  curl                          \
  fail2ban                      \
  git                           \
  gnupg2                        \
  htop                          \
  iftop                         \
  make                          \
  man                           \
  nano                          \
  netcat                        \
  openssh-server                \
  openssl                       \
  rsync                         \
  screen                        \
  shellcheck                    \
  software-properties-common    \
  tldr                          \
  tree                          \
  ufw                           \
  unattended-upgrades           \
  unzip                         \
  vim                           \
  wget


# configure firewall
echo " → Setting up firewall"
if [ "$SETUP_DISABLE_IPV6" = true ];
then
  echo "IPV6=no" >> /etc/ufw/ufw.conf
  systemctl restart ufw
fi
ufw logging on
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh/tcp
ufw --force enable


if [ "$SETUP_INSTALL_DOCKER" = true ];
then
  # install docker
  echo " → Installing Docker"
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
  sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
  apt-get -qy update
  apt-get -qy install docker-ce
  systemctl enable docker
  # enable memory limit and swap accounting
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"/g' /etc/default/grub
  update-grub
  SETUP_REQUIRES_REBOOT=true
  # install docker-compose 1.24.1
  curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
fi


# clean up apt packages
echo " → Cleaning up apt packages"
apt-get -qy autoremove
apt-get -qy clean


SETUP_PRINT_PASSWORD=false

# add admin user
if id "$SETUP_USER";
then
  echo " → User $SETUP_USER already exists"
else
  echo " → Adding user $SETUP_USER"
  adduser --quiet --disabled-password --gecos "" "$SETUP_USER"
  gpasswd -a "$SETUP_USER" sudo
  SETUP_PASS="$(openssl rand -base64 14)"
  echo "$SETUP_USER:$SETUP_PASS" | chpasswd
  SETUP_PRINT_PASSWORD=true
fi


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
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""
echo " → Generating rsa ssh server key"
ssh-keygen -t rsa -b 8192 -f ssh_host_rsa_key -N ""

# restart sshd
echo " → Restarting sshd"
systemctl restart sshd


echo "########"
if [ "$SETUP_PRINT_PASSWORD" = true ];
then
  echo " → Password for $SETUP_USER is: $SETUP_PASS"
fi
if [ "$SETUP_REQUIRES_REBOOT" = true ];
then
  echo " → Please reboot the machine for certain changes to take effect!"
fi
echo " → Script finished!"
echo "########"
