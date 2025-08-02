# LEMP Stack Installer

A simple and automated Bash script to install a full web server stack on Ubuntu. Includes NGINX, PHP, MariaDB, Fail2Ban, Swapfile setup, and basic firewall rules using iptables.

## Features

- Supports Ubuntu **22.04** and **24.04**
- Automatically installs and configures:
  - NGINX with custom configuration
  - PHP 8.3 and common extensions
  - MariaDB 11.4 with tunning
  - Fail2Ban (WordPress & MySQL protection)
  - 2GB Swapfile
  - iptables firewall rules (SSH, HTTP, HTTPS)

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/iodesk/lemp.git
   cd lemp
2. Direct
   ```bash
   bash <(curl -fsSL https://vps.fio.link/install.sh)
