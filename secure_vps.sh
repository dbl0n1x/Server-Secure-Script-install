#!/usr/bin/env bash

set -e

echo "[+] Updating system..."
apt update && apt upgrade -y

echo "[+] Installing base security packages..."
apt install -y \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    auditd \
    logwatch \
    curl \
    vim \
    htop \
    net-tools \
    ca-certificates

echo "[+] Enabling unattended security updates..."
dpkg-reconfigure --priority=low unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF


echo "[+] Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
EOF

systemctl enable fail2ban
systemctl restart fail2ban


echo "[+] Hardening SSH config..."

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config

systemctl restart ssh


echo "[+] Enabling audit daemon..."

systemctl enable auditd
systemctl start auditd


echo "[+] Applying kernel hardening (sysctl)..."

cat >> /etc/sysctl.conf <<EOF

# IP spoofing protection
net.ipv4.conf.all.rp_filter=1

# Disable source routing
net.ipv4.conf.all.accept_source_route=0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0

# Log suspicious packets
net.ipv4.conf.all.log_martians=1

# SYN flood protection
net.ipv4.tcp_syncookies=1
EOF

sysctl -p


echo "[+] Setting up automatic log monitoring..."

cat > /etc/cron.daily/logwatch <<EOF
#!/bin/bash
/usr/sbin/logwatch --output stdout --format text --range yesterday
EOF

chmod +x /etc/cron.daily/logwatch


echo "[+] Disabling unused services..."

systemctl disable avahi-daemon 2>/dev/null || true
systemctl disable cups 2>/dev/null || true


echo "[+] Security setup complete!"
