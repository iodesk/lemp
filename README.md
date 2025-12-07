# LEMP Stack Installer

A simple and automated Bash script to install a full web server stack on Ubuntu. Includes NGINX, PHP, MariaDB, Fail2Ban, Swapfile setup, and basic firewall rules using iptables.

## Features

- Supports Ubuntu **22.04** and **24.04**
- Automatically installs and configures:
  - NGINX with with with tunning
  - PHP 8.3 with with tunning and common extensions
  - MariaDB 11.4 with tunning
  - Phpmyadmin
  - Fail2Ban (WordPress & MySQL protection)
  - Redis
  - 2GB Swapfile
  - iptables firewall rules (SSH, HTTP, HTTPS)

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/iodesk/lemp.git
   cd lemp
   ```
2. Direct Install
   ```bash
   bash <(curl -fsSL https://vps.fio.link/install.sh)
   ```
3. Direct Uninstall
   ```bash
   bash <(curl -fsSL https://vps.fio.link/uninstall.sh)
   ```
4. Add WP site
   - Letsencrypt
   ```bash
   bash <(curl -fsSL https://vps.fio.link/add-site.sh) -d domain.com -php 8.3 -ssl le
   ```
   - Selfcert
   ```bash
   bash <(curl -fsSL https://vps.fio.link/add-site.sh) -d domain.com -php 8.3 -ssl self
   ```
   - None
   ```bash
   bash <(curl -fsSL https://vps.fio.link/add-site.sh) -d domain.com -php 8.3 -ssl none
   ```
6. Remove WP site
   ```bash
   bash <(curl -fsSL https://vps.fio.link/rm-site.sh) -d domain.com
   ```
