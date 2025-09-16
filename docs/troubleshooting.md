# Troubleshooting Guide - AdGuard Home Infrastructure

This comprehensive troubleshooting guide helps you diagnose and resolve common issues with your AdGuard Home Infrastructure deployment.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [DNS Resolution Issues](#dns-resolution-issues)
3. [Service Connectivity Problems](#service-connectivity-problems)
4. [Performance Issues](#performance-issues)
5. [Container Problems](#container-problems)
6. [Network Configuration Issues](#network-configuration-issues)
7. [Security and Access Issues](#security-and-access-issues)
8. [Monitoring and Alerting Issues](#monitoring-and-alerting-issues)
9. [Backup and Recovery Issues](#backup-and-recovery-issues)
10. [Australian-Specific Issues](#australian-specific-issues)

## Quick Diagnostics

### Health Check Commands

#### Immediate Status Check
```bash
# Run comprehensive health check
make health

# Check all service status
docker-compose ps

# Test DNS functionality
dig @localhost google.com

# Check web interfaces
curl -I http://localhost:3000/  # AdGuard
curl -I http://localhost:3001/  # Grafana
curl -I http://localhost:9090/  # Prometheus
```

#### System Resource Check
```bash
# Check system resources
free -h                         # Memory usage
df -h                          # Disk usage
top                            # CPU usage
netstat -tulpn                 # Network connections
```

#### Log Analysis
```bash
# Check system logs
journalctl -f                  # Real-time system logs
docker-compose logs -f         # Container logs
tail -f /opt/logs/*.log       # Application logs

# Check specific service logs
docker-compose logs adguard
docker-compose logs prometheus
docker-compose logs grafana
```

### Emergency Recovery Commands

#### Service Recovery
```bash
# Restart all services
make restart

# Restart specific service
docker-compose restart adguard

# Full reset (nuclear option)
docker-compose down
docker-compose up -d
```

#### Network Recovery
```bash
# Reset network configuration
sudo netplan apply
sudo systemctl restart networking

# Reset firewall
sudo ufw --force reset
sudo ./configs/firewall/ufw-rules.sh
```

## DNS Resolution Issues

### Issue: DNS Not Resolving

#### Symptoms
- Websites not loading
- `dig` commands timing out
- DNS queries failing

#### Diagnosis
```bash
# Test DNS service
sudo netstat -tulpn | grep :53
ss -tulpn | grep :53

# Check AdGuard container
docker-compose ps adguard
docker-compose logs adguard

# Test direct DNS queries
dig @127.0.0.1 google.com
dig @192.168.1.100 google.com
```

#### Solutions
```bash
# Solution 1: Restart AdGuard service
docker-compose restart adguard

# Solution 2: Check port conflicts
sudo lsof -i :53
# Kill conflicting processes if found

# Solution 3: Verify configuration
cat /opt/adguard/conf/AdGuardHome.yaml | grep -A 5 "bind_hosts"

# Solution 4: Reset DNS configuration
docker-compose down adguard
rm -f /opt/adguard/conf/AdGuardHome.yaml
cp docker/configs/adguard/AdGuardHome.yaml /opt/adguard/conf/
docker-compose up -d adguard
```

### Issue: Slow DNS Resolution

#### Symptoms
- Long website loading times
- DNS queries taking >500ms
- Timeouts on some queries

#### Diagnosis
```bash
# Test query performance
time dig @localhost google.com
time dig @localhost facebook.com

# Compare with upstream
time dig @1.1.1.1 google.com
time dig @8.8.8.8 google.com

# Check AdGuard statistics
curl -s http://localhost:3000/control/stats | jq '.'
```

#### Solutions
```bash
# Solution 1: Optimize upstream DNS
# Edit .env file
DNS_UPSTREAM_1=1.1.1.1
DNS_UPSTREAM_2=8.8.8.8
DNS_UPSTREAM_3=9.9.9.9

# Restart AdGuard
docker-compose restart adguard

# Solution 2: Increase cache settings
# Edit AdGuard configuration
cache_size: 8388608  # Increase cache

# Solution 3: Check network connectivity
ping 1.1.1.1
ping 8.8.8.8
traceroute 1.1.1.1
```

### Issue: DNS Blocking Not Working

#### Symptoms
- Ads still showing on websites
- Known malicious domains resolving
- Blocked domains returning valid IPs

#### Diagnosis
```bash
# Test blocked domains
dig @localhost doubleclick.net
dig @localhost googleadservices.com

# Check filter lists
curl -s http://localhost:3000/control/filtering/status | jq '.'

# Verify blocking rules
curl -s http://localhost:3000/control/rewrite/list | jq '.'
```

#### Solutions
```bash
# Solution 1: Update filter lists
curl -X POST http://localhost:3000/control/filtering/refresh

# Solution 2: Check filtering status
curl -s http://localhost:3000/control/filtering/status
# If disabled, enable it:
curl -X POST http://localhost:3000/control/filtering/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# Solution 3: Add custom blocking rules
# Via web interface or API
curl -X POST http://localhost:3000/control/filtering/add_url \
  -H "Content-Type: application/json" \
  -d '{"name": "Custom Block", "url": "||doubleclick.net^"}'
```

## Service Connectivity Problems

### Issue: AdGuard Web Interface Not Accessible

#### Symptoms
- Cannot access http://192.168.1.100:3000
- Connection refused or timeout
- Browser shows "This site can't be reached"

#### Diagnosis
```bash
# Check container status
docker-compose ps adguard

# Check port binding
sudo netstat -tulpn | grep :3000
docker port adguard-home

# Check firewall rules
sudo ufw status | grep 3000

# Test from server
curl -I http://localhost:3000/
curl -I http://127.0.0.1:3000/
```

#### Solutions
```bash
# Solution 1: Restart AdGuard container
docker-compose restart adguard

# Solution 2: Check firewall rules
sudo ufw allow from 192.168.0.0/16 to any port 3000

# Solution 3: Verify container networking
docker network ls
docker network inspect adguard-net

# Solution 4: Reset container
docker-compose down adguard
docker-compose up -d adguard
```

### Issue: SSH Access Problems

#### Symptoms
- Cannot SSH to server
- Connection refused on port 2222
- Authentication failures

#### Diagnosis
```bash
# Check SSH service status
sudo systemctl status ssh

# Check SSH configuration
sudo grep -E "Port|PasswordAuthentication|PubkeyAuthentication" /etc/ssh/sshd_config

# Check firewall rules
sudo ufw status | grep 2222

# Test SSH connectivity
ssh -p 2222 -v adguard@192.168.1.100
```

#### Solutions
```bash
# Solution 1: Restart SSH service
sudo systemctl restart ssh

# Solution 2: Check SSH configuration
sudo nano /etc/ssh/sshd_config
# Verify:
# Port 2222
# PasswordAuthentication no
# PubkeyAuthentication yes

# Solution 3: Check user account
id adguard
sudo passwd adguard  # If password needed

# Solution 4: Regenerate SSH keys
ssh-keygen -t ed25519 -f ~/.ssh/adguard_key
ssh-copy-id -i ~/.ssh/adguard_key.pub -p 2222 adguard@192.168.1.100
```

### Issue: Monitoring Services Not Working

#### Symptoms
- Grafana not loading
- Prometheus targets down
- No metrics data available

#### Diagnosis
```bash
# Check all monitoring containers
docker-compose ps prometheus grafana alertmanager

# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'

# Check Grafana health
curl -s http://localhost:3001/api/health

# Check container logs
docker-compose logs prometheus
docker-compose logs grafana
```

#### Solutions
```bash
# Solution 1: Restart monitoring stack
docker-compose restart prometheus grafana alertmanager

# Solution 2: Check configuration files
# Validate Prometheus config
docker exec prometheus promtool check config /etc/prometheus/prometheus.yml

# Solution 3: Reset data directories
docker-compose down
sudo rm -rf /opt/monitoring/prometheus/data/*
sudo rm -rf /opt/monitoring/grafana/data/*
docker-compose up -d

# Solution 4: Check networking
docker exec prometheus wget -O- http://adguard-exporter:9617/metrics
```

## Performance Issues

### Issue: High CPU Usage

#### Symptoms
- System sluggish
- High load average
- Container CPU usage >80%

#### Diagnosis
```bash
# Check system load
uptime
top -p $(pgrep -d, -f docker)

# Check container resource usage
docker stats --no-stream

# Identify high CPU processes
htop
ps aux --sort=-%cpu | head -10
```

#### Solutions
```bash
# Solution 1: Adjust resource limits
# Edit docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '2.0'  # Increase CPU limit

# Solution 2: Optimize AdGuard settings
# Reduce query logging
querylog:
  size_memory: 500  # Reduce from 1000

# Solution 3: Check for DNS amplification attacks
tail -f /opt/adguard/logs/querylog.json | grep -E "(large|unusual)"

# Solution 4: Implement rate limiting
# Edit AdGuard config
ratelimit: 10  # Reduce from 20
```

### Issue: High Memory Usage

#### Symptoms
- System running out of memory
- OOM killer activating
- Containers restarting unexpectedly

#### Diagnosis
```bash
# Check memory usage
free -h
cat /proc/meminfo

# Check container memory usage
docker stats --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Check for memory leaks
dmesg | grep -i "killed process"
journalctl -u docker | grep -i "oom"
```

#### Solutions
```bash
# Solution 1: Increase memory limits
# Edit docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1g  # Increase limit

# Solution 2: Reduce cache sizes
# AdGuard cache
cache_size: 2097152  # Reduce cache size

# Prometheus retention
--storage.tsdb.retention.time=15d  # Reduce retention

# Solution 3: Enable swap (if appropriate)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Solution 4: Restart high-memory containers
docker-compose restart prometheus
```

### Issue: Slow Website Loading

#### Symptoms
- Websites take long to load
- DNS queries slow
- Poor browsing experience

#### Diagnosis
```bash
# Test DNS performance
time nslookup google.com
time nslookup facebook.com

# Check network latency
ping 1.1.1.1
ping 8.8.8.8
traceroute google.com

# Monitor real-time DNS queries
tail -f /opt/adguard/logs/querylog.json
```

#### Solutions
```bash
# Solution 1: Optimize DNS upstreams
# Use closest geographic servers
DNS_UPSTREAM_1=1.1.1.1  # Cloudflare Sydney
DNS_UPSTREAM_2=8.8.8.8  # Google Sydney

# Solution 2: Increase cache TTL
# Edit AdGuard configuration
cache_ttl_min: 300   # 5 minutes minimum
cache_ttl_max: 3600  # 1 hour maximum

# Solution 3: Enable DNS prefetching
# In browser or router settings

# Solution 4: Check for blocking false positives
# Review query logs for legitimate sites being blocked
```

## Container Problems

### Issue: Container Won't Start

#### Symptoms
- Container status shows "Exited"
- Services not accessible
- Container constantly restarting

#### Diagnosis
```bash
# Check container status
docker-compose ps

# Check container logs
docker-compose logs [service_name]

# Check for port conflicts
sudo netstat -tulpn | grep -E ":53|:3000|:9090"

# Check disk space
df -h
```

#### Solutions
```bash
# Solution 1: Restart with fresh logs
docker-compose down [service_name]
docker-compose up -d [service_name]

# Solution 2: Check configuration syntax
# For AdGuard
yq eval /opt/adguard/conf/AdGuardHome.yaml

# For Prometheus
docker run --rm -v /opt/monitoring/prometheus:/config \
  prom/prometheus promtool check config /config/prometheus.yml

# Solution 3: Reset container data
docker-compose down [service_name]
sudo rm -rf /opt/[service]/data/*
docker-compose up -d [service_name]

# Solution 4: Pull fresh images
docker-compose pull [service_name]
docker-compose up -d [service_name]
```

### Issue: Container Networking Problems

#### Symptoms
- Containers can't communicate
- External connectivity issues
- DNS resolution between containers failing

#### Diagnosis
```bash
# Check Docker networks
docker network ls
docker network inspect adguard-net

# Test container connectivity
docker exec adguard-home ping prometheus
docker exec prometheus ping adguard-exporter

# Check DNS resolution in containers
docker exec adguard-home nslookup prometheus
```

#### Solutions
```bash
# Solution 1: Recreate network
docker-compose down
docker network rm adguard-infrastructure_adguard-net
docker-compose up -d

# Solution 2: Check firewall rules
sudo ufw status
# Ensure Docker networks are allowed

# Solution 3: Restart Docker daemon
sudo systemctl restart docker
docker-compose up -d

# Solution 4: Check Docker daemon configuration
cat /etc/docker/daemon.json
```

### Issue: Container Data Loss

#### Symptoms
- Configuration lost after restart
- Metrics data missing
- Settings reset to defaults

#### Diagnosis
```bash
# Check volume mounts
docker-compose config | grep -A 5 volumes

# Check file permissions
ls -la /opt/adguard/
ls -la /opt/monitoring/

# Check available disk space
df -h /opt/
```

#### Solutions
```bash
# Solution 1: Fix permissions
sudo chown -R 1000:1000 /opt/adguard/
sudo chown -R 1000:1000 /opt/monitoring/

# Solution 2: Restore from backup
/opt/scripts/backup/restore.sh

# Solution 3: Recreate volumes with proper ownership
docker-compose down
sudo rm -rf /opt/adguard/data /opt/monitoring/*/data
mkdir -p /opt/adguard/{data,conf} /opt/monitoring/{prometheus,grafana}/data
sudo chown -R 1000:1000 /opt/adguard /opt/monitoring
docker-compose up -d

# Solution 4: Check backup schedule
crontab -l | grep backup
```

## Network Configuration Issues

### Issue: Static IP Not Working

#### Symptoms
- Server getting dynamic IP
- IP address conflicts
- Network connectivity issues

#### Diagnosis
```bash
# Check current IP configuration
ip addr show
ip route show

# Check netplan configuration
cat /etc/netplan/*.yaml

# Check DHCP lease
dhclient -v
```

#### Solutions
```bash
# Solution 1: Reconfigure netplan
sudo nano /etc/netplan/01-netcfg.yaml
# Add static configuration:
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]

sudo netplan apply

# Solution 2: Release and renew DHCP
sudo dhclient -r
sudo dhclient

# Solution 3: Check router DHCP reservation
# Configure MAC-based IP reservation in router

# Solution 4: Restart networking
sudo systemctl restart systemd-networkd
```

### Issue: Firewall Blocking Connections

#### Symptoms
- Cannot access services from other devices
- Connections timing out
- SSH access denied

#### Diagnosis
```bash
# Check UFW status
sudo ufw status verbose

# Check iptables rules
sudo iptables -L -n

# Test port accessibility
telnet 192.168.1.100 3000
nmap -p 53,2222,3000 192.168.1.100
```

#### Solutions
```bash
# Solution 1: Reset and reconfigure UFW
sudo ufw --force reset
./configs/firewall/ufw-rules.sh

# Solution 2: Allow specific connections
sudo ufw allow from 192.168.0.0/16 to any port 3000
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# Solution 3: Temporarily disable for testing
sudo ufw disable
# Test connectivity, then re-enable
sudo ufw enable

# Solution 4: Check fail2ban blocks
sudo fail2ban-client status
sudo fail2ban-client set adguard-auth unbanip [IP_ADDRESS]
```

### Issue: Router Integration Problems

#### Symptoms
- Devices not using AdGuard for DNS
- DNS settings not propagating
- Some devices bypassing filtering

#### Diagnosis
```bash
# Check DHCP settings on router
# Look for DNS server configuration

# Test DNS from client device
nslookup google.com
# Should show 192.168.1.100 as server

# Check device DNS settings
# Windows: ipconfig /all
# Linux: systemd-resolve --status
# Mac: scutil --dns
```

#### Solutions
```bash
# Solution 1: Configure router DHCP
# Set Primary DNS: 192.168.1.100
# Set Secondary DNS: 1.1.1.1

# Solution 2: Set manual DNS on devices
# Configure each device individually if DHCP fails

# Solution 3: Use DHCP option 6
# Configure router to push DNS via DHCP option 6

# Solution 4: Block external DNS (advanced)
# Block ports 53/853 to external IPs on router
# Force all DNS through AdGuard
```

## Security and Access Issues

### Issue: SSH Key Authentication Failing

#### Symptoms
- "Permission denied (publickey)" errors
- Cannot SSH with keys
- Forced to use password authentication

#### Diagnosis
```bash
# Test SSH with verbose output
ssh -p 2222 -vvv adguard@192.168.1.100

# Check authorized keys
cat ~/.ssh/authorized_keys

# Check SSH server logs
sudo journalctl -u ssh -f
```

#### Solutions
```bash
# Solution 1: Fix key permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa

# Solution 2: Regenerate SSH keys
ssh-keygen -t ed25519 -C "adguard-new"
ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 adguard@192.168.1.100

# Solution 3: Check SSH server configuration
sudo nano /etc/ssh/sshd_config
# Ensure:
# PubkeyAuthentication yes
# AuthorizedKeysFile .ssh/authorized_keys

sudo systemctl restart ssh

# Solution 4: Temporarily enable password auth for recovery
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication yes
sudo systemctl restart ssh
# Fix keys, then disable password auth again
```

### Issue: Fail2ban Blocking Legitimate IPs

#### Symptoms
- Cannot connect from known good IPs
- Users getting blocked unexpectedly
- Services timing out from specific locations

#### Diagnosis
```bash
# Check fail2ban status
sudo fail2ban-client status

# Check banned IPs
sudo fail2ban-client status sshd-adguard
sudo fail2ban-client status adguard-auth

# Check fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

#### Solutions
```bash
# Solution 1: Unban specific IP
sudo fail2ban-client set sshd-adguard unbanip [IP_ADDRESS]
sudo fail2ban-client set adguard-auth unbanip [IP_ADDRESS]

# Solution 2: Whitelist trusted IPs
sudo nano /etc/fail2ban/jail.d/adguard.conf
# Add: ignoreip = 192.168.1.0/24 [trusted_ip]

sudo systemctl restart fail2ban

# Solution 3: Adjust thresholds
# Increase maxretry or findtime values
maxretry = 10    # Instead of 5
findtime = 1200  # Instead of 600

# Solution 4: Temporarily disable specific jail
sudo fail2ban-client stop adguard-auth
```

### Issue: TLS/SSL Certificate Problems

#### Symptoms
- Browser security warnings
- HTTPS connections failing
- Certificate validation errors

#### Diagnosis
```bash
# Check certificate status
openssl s_client -connect 192.168.1.100:443 -servername adguard.home.local

# Check certificate files
ls -la /opt/adguard/conf/ssl/

# Test certificate validity
openssl x509 -in certificate.crt -text -noout
```

#### Solutions
```bash
# Solution 1: Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
sudo cp cert.pem key.pem /opt/adguard/conf/ssl/

# Solution 2: Use Let's Encrypt (if domain available)
sudo certbot certonly --standalone -d adguard.yourdomain.com

# Solution 3: Disable HTTPS temporarily
# Edit AdGuard configuration
tls:
  enabled: false

# Solution 4: Import certificate to browsers/devices
# Export and import the self-signed certificate
```

## Monitoring and Alerting Issues

### Issue: Prometheus Not Collecting Metrics

#### Symptoms
- Empty Grafana dashboards
- No metrics in Prometheus
- Targets showing as down

#### Diagnosis
```bash
# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'

# Check exporter endpoints
curl http://localhost:9617/metrics  # AdGuard exporter
curl http://localhost:9100/metrics  # Node exporter

# Check Prometheus logs
docker-compose logs prometheus
```

#### Solutions
```bash
# Solution 1: Restart Prometheus
docker-compose restart prometheus

# Solution 2: Check configuration
docker exec prometheus promtool check config /etc/prometheus/prometheus.yml

# Solution 3: Fix network connectivity
docker exec prometheus wget -O- http://adguard-exporter:9617/metrics

# Solution 4: Reset Prometheus data
docker-compose down prometheus
sudo rm -rf /opt/monitoring/prometheus/data/*
docker-compose up -d prometheus
```

### Issue: Grafana Dashboards Not Loading

#### Symptoms
- Blank dashboards
- "No data" messages
- Dashboard import failures

#### Diagnosis
```bash
# Check Grafana logs
docker-compose logs grafana

# Check data source configuration
curl -u admin:password http://localhost:3001/api/datasources

# Test Prometheus connectivity from Grafana
docker exec grafana wget -O- http://prometheus:9090/api/v1/query?query=up
```

#### Solutions
```bash
# Solution 1: Reconfigure data source
# Access Grafana → Configuration → Data Sources
# Update Prometheus URL to: http://prometheus:9090

# Solution 2: Re-import dashboards
# Delete existing dashboards
# Import from dashboard ID or JSON file

# Solution 3: Reset Grafana data
docker-compose down grafana
sudo rm -rf /opt/monitoring/grafana/data/*
docker-compose up -d grafana

# Solution 4: Check permissions
sudo chown -R 472:472 /opt/monitoring/grafana/data/
```

### Issue: Alerts Not Working

#### Symptoms
- No email/Slack notifications
- Alerts not triggering
- Alertmanager showing errors

#### Diagnosis
```bash
# Check Alertmanager status
curl http://localhost:9093/api/v1/status

# Check alert rules
curl http://localhost:9090/api/v1/rules

# Check Alertmanager logs
docker-compose logs alertmanager
```

#### Solutions
```bash
# Solution 1: Verify email configuration
# Check SMTP settings in .env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Solution 2: Test SMTP connectivity
telnet smtp.gmail.com 587

# Solution 3: Check Alertmanager configuration
docker exec alertmanager amtool check-config /etc/alertmanager/alertmanager.yml

# Solution 4: Send test alert
curl -H "Content-Type: application/json" -d '[{"labels":{"alertname":"test"}}]' http://localhost:9093/api/v1/alerts
```

## Backup and Recovery Issues

### Issue: Backup Failures

#### Symptoms
- Backup scripts failing
- No recent backups created
- Backup corruption errors

#### Diagnosis
```bash
# Check backup logs
tail -f /opt/logs/backup.log

# Check backup directory
ls -la /opt/backups/

# Test backup script manually
sudo /opt/scripts/backup/backup.sh
```

#### Solutions
```bash
# Solution 1: Fix permissions
sudo chown -R adguard:adguard /opt/backups/
sudo chmod 755 /opt/backups/

# Solution 2: Check disk space
df -h /opt/backups/

# Solution 3: Fix backup script
sudo chmod +x /opt/scripts/backup/backup.sh

# Solution 4: Test encryption
openssl enc -aes-256-cbc -salt -in testfile -out testfile.enc -k "test_key"
```

### Issue: Restore Failures

#### Symptoms
- Cannot restore from backup
- Corrupted backup files
- Restore script errors

#### Diagnosis
```bash
# Verify backup integrity
sha256sum -c /opt/backups/latest-backup.sha256

# Test backup extraction
tar -tzf /opt/backups/latest-backup.tar.gz

# Check restore script
/opt/scripts/backup/restore.sh --dry-run
```

#### Solutions
```bash
# Solution 1: Use different backup
ls -t /opt/backups/*.tar.gz | head -5

# Solution 2: Manual restoration
tar -xzf backup.tar.gz
sudo cp -r extracted-data/* /opt/adguard/

# Solution 3: Verify backup encryption
openssl enc -aes-256-cbc -d -in backup.tar.gz.enc -out backup.tar.gz -k "encryption_key"

# Solution 4: Restore individual components
# Restore only AdGuard configuration
tar -xzf backup.tar.gz adguard/conf/
```

## Australian-Specific Issues

### Issue: Poor Performance with Australian Sites

#### Symptoms
- Slow loading of .com.au sites
- High latency to Australian services
- Overseas DNS resolution

#### Diagnosis
```bash
# Test Australian site performance
time dig @localhost bom.gov.au
time dig @localhost abc.net.au
time dig @localhost commbank.com.au

# Check upstream DNS latency
ping 1.1.1.1    # Cloudflare Sydney
ping 8.8.8.8    # Google Sydney
ping 9.9.9.9    # Quad9
```

#### Solutions
```bash
# Solution 1: Prioritize Australian DNS servers
DNS_UPSTREAM_1=1.1.1.1    # Cloudflare Sydney PoP
DNS_UPSTREAM_2=8.8.8.8    # Google Sydney PoP
DNS_UPSTREAM_3=1.0.0.1    # Cloudflare secondary

# Solution 2: Add Australian-specific DNS
DNS_UPSTREAM_4=203.12.160.35  # Telstra/Optus DNS

# Solution 3: Optimize for Australian CDNs
# Add specific rules for Australian content
- '@@||cdn.australia.com^'
- '@@||*.cloudfront.com^'  # Amazon CloudFront Sydney
```

### Issue: ISP-Specific Problems

#### Symptoms
- Connection issues with specific ISPs
- DNS blocking by ISP
- Performance varies by ISP

#### Diagnosis
```bash
# Identify ISP
curl ipinfo.io

# Test ISP DNS
dig @[isp_dns] google.com

# Check for ISP blocking
telnet 1.1.1.1 53
telnet 8.8.8.8 53
```

#### Solutions
```bash
# Solution 1: Use DNS-over-HTTPS
# Force encrypted DNS to bypass ISP filtering
DNS_UPSTREAM_DOH_1=https://1.1.1.1/dns-query
DNS_UPSTREAM_DOH_2=https://dns.google/dns-query

# Solution 2: Add ISP-specific configuration
# Telstra
DNS_UPSTREAM_TELSTRA=139.130.4.5

# Optus
DNS_UPSTREAM_OPTUS=211.29.132.12

# TPG/iiNet
DNS_UPSTREAM_TPG=203.12.160.35

# Solution 3: Configure for NBN
# Optimize for NBN connection types
# Consider HFC vs FTTN vs FTTP differences
```

### Issue: Government Website Access

#### Symptoms
- Cannot access .gov.au sites
- MyGov login issues
- Government service problems

#### Diagnosis
```bash
# Test government sites
dig @localhost mygovid.gov.au
dig @localhost ato.gov.au
dig @localhost centrelink.gov.au

# Check for blocking
curl -I https://mygovid.gov.au
```

#### Solutions
```bash
# Solution 1: Whitelist government domains
# Add to AdGuard whitelist
- '@@||gov.au^'
- '@@||mygovid.gov.au^'
- '@@||ato.gov.au^'
- '@@||centrelink.gov.au^'

# Solution 2: Disable filtering for government sites
# Create custom rule
||gov.au^$important

# Solution 3: Use different DNS for government queries
# Configure selective DNS routing
```

### Issue: Banking Website Problems

#### Symptoms
- Online banking not working
- Payment systems failing
- Bank apps not connecting

#### Diagnosis
```bash
# Test major Australian banks
dig @localhost commbank.com.au
dig @localhost westpac.com.au
dig @localhost anz.com
dig @localhost nab.com.au

# Check HTTPS connectivity
curl -I https://www.commbank.com.au
```

#### Solutions
```bash
# Solution 1: Whitelist banking domains
# Add comprehensive banking whitelist
- '@@||commbank.com.au^'
- '@@||westpac.com.au^'
- '@@||anz.com^'
- '@@||nab.com.au^'
- '@@||bankwest.com.au^'
- '@@||macquarie.com.au^'

# Solution 2: Disable filtering for financial services
# Create financial services exception
||*.bank^$important
||*.credit^$important

# Solution 3: Use bank-specific DNS when needed
# Temporarily bypass for banking
```

---

## Getting Additional Help

### Community Resources
- **GitHub Issues**: Report bugs and get community help
- **Discussion Forums**: Community Q&A and troubleshooting
- **Wiki Documentation**: Extended troubleshooting scenarios

### Professional Support
- **Email Support**: technical-support@example.com
- **Professional Services**: Custom configuration and enterprise support
- **Training**: Australian-specific deployment training

### Emergency Support
For critical production issues:
1. Follow emergency recovery procedures above
2. Collect diagnostic information
3. Contact support with detailed logs
4. Consider temporary bypass while resolving

Remember to always backup your configuration before making significant changes!