# Deployment Guide - Advisory Intelligence API

This guide explains how to deploy the Advisory Intelligence API as a systemd service on your Linux VM, so it runs continuously even after you close the terminal.

## Prerequisites

- Linux VM with systemd (Ubuntu, CentOS, RHEL, etc.)
- Python 3.10.12 installed via pyenv
- Application already working when run with `./start.sh`
- sudo/root access

## Deployment Steps

### 1. Create Logs Directory

```bash
cd /path/to/Advisory_Intelligence
mkdir -p logs
```

### 2. Update Service File

Edit `advisory-intelligence.service` and replace the following placeholders:

- `YOUR_USERNAME` - Your Linux username (e.g., `ubuntu`, `ec2-user`, etc.)
- `/path/to/Advisory_Intelligence` - Full path to your project directory

**Example:**
```ini
User=ubuntu
WorkingDirectory=/home/ubuntu/Advisory_Intelligence
Environment="PATH=/home/ubuntu/.pyenv/versions/3.10.12/bin:..."
EnvironmentFile=/home/ubuntu/Advisory_Intelligence/.env
ExecStart=/home/ubuntu/Advisory_Intelligence/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
StandardOutput=append:/home/ubuntu/Advisory_Intelligence/logs/advisory-intelligence.log
StandardError=append:/home/ubuntu/Advisory_Intelligence/logs/advisory-intelligence-error.log
```

### 3. Install the Service

```bash
# Copy service file to systemd directory
sudo cp advisory-intelligence.service /etc/systemd/system/

# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable advisory-intelligence

# Start the service
sudo systemctl start advisory-intelligence
```

### 4. Verify Service is Running

```bash
# Check service status
sudo systemctl status advisory-intelligence

# Should show:
# ● advisory-intelligence.service - Advisory Intelligence API Service
#    Loaded: loaded (/etc/systemd/system/advisory-intelligence.service; enabled)
#    Active: active (running) since ...
```

### 5. Test the API

```bash
# Test health endpoint
curl http://localhost:8000/health

# Should return:
# {"status":"healthy","service":"Advisory Intelligence API"}
```

## Service Management Commands

### Start Service
```bash
sudo systemctl start advisory-intelligence
```

### Stop Service
```bash
sudo systemctl stop advisory-intelligence
```

### Restart Service
```bash
sudo systemctl restart advisory-intelligence
```

### Check Status
```bash
sudo systemctl status advisory-intelligence
```

### View Logs
```bash
# View application logs
tail -f logs/advisory-intelligence.log

# View error logs
tail -f logs/advisory-intelligence-error.log

# View systemd logs
sudo journalctl -u advisory-intelligence -f
```

### Disable Service (prevent auto-start on boot)
```bash
sudo systemctl disable advisory-intelligence
```

## Updating the Application

When you update the code:

```bash
# 1. Pull latest changes
git pull

# 2. Install any new dependencies
source .venv/bin/activate
pip install -r requirements.txt

# 3. Restart the service
sudo systemctl restart advisory-intelligence

# 4. Check status
sudo systemctl status advisory-intelligence
```

## Troubleshooting

### Service Won't Start

1. **Check logs:**
   ```bash
   sudo journalctl -u advisory-intelligence -n 50
   ```

2. **Verify paths in service file:**
   ```bash
   cat /etc/systemd/system/advisory-intelligence.service
   ```

3. **Test manually:**
   ```bash
   cd /path/to/Advisory_Intelligence
   source .venv/bin/activate
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

### Port Already in Use

```bash
# Find process using port 8000
sudo lsof -i :8000

# Kill the process
sudo kill -9 <PID>

# Restart service
sudo systemctl restart advisory-intelligence
```

### Permission Issues

```bash
# Ensure correct ownership
sudo chown -R YOUR_USERNAME:YOUR_USERNAME /path/to/Advisory_Intelligence

# Ensure logs directory is writable
chmod 755 logs
```

### Database Connection Issues

1. **Check .env file:**
   ```bash
   cat .env | grep DB_
   ```

2. **Test database connection:**
   ```bash
   psql -h $DB_HOST -p $DB_PORT -U $DB_USERNAME -d $DB_NAME
   ```

3. **Check if PostgreSQL is running:**
   ```bash
   sudo systemctl status postgresql
   ```

## Alternative: Using nohup (Quick Solution)

If you don't have sudo access or prefer a simpler approach:

```bash
# Start in background with nohup
cd /path/to/Advisory_Intelligence
source .venv/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > logs/app.log 2>&1 &

# Save the process ID
echo $! > app.pid

# To stop:
kill $(cat app.pid)
```

## Alternative: Using screen or tmux

### Using screen:
```bash
# Start a screen session
screen -S advisory-api

# Run the application
cd /path/to/Advisory_Intelligence
./start.sh

# Detach from screen: Press Ctrl+A, then D

# Reattach to screen
screen -r advisory-api

# Kill screen session
screen -X -S advisory-api quit
```

### Using tmux:
```bash
# Start a tmux session
tmux new -s advisory-api

# Run the application
cd /path/to/Advisory_Intelligence
./start.sh

# Detach from tmux: Press Ctrl+B, then D

# Reattach to tmux
tmux attach -t advisory-api

# Kill tmux session
tmux kill-session -t advisory-api
```

## Production Recommendations

### 1. Use a Reverse Proxy (Nginx)

Create `/etc/nginx/sites-available/advisory-intelligence`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/advisory-intelligence /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 2. Add SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 3. Set Up Log Rotation

Create `/etc/logrotate.d/advisory-intelligence`:

```
/path/to/Advisory_Intelligence/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 YOUR_USERNAME YOUR_USERNAME
    sharedscripts
    postrotate
        systemctl reload advisory-intelligence > /dev/null 2>&1 || true
    endscript
}
```

### 4. Monitor with systemd

```bash
# Enable email notifications on failure (requires mail setup)
sudo systemctl edit advisory-intelligence

# Add:
[Service]
OnFailure=status-email@%n.service
```

## Security Checklist

- [ ] Change default database passwords
- [ ] Use environment variables for secrets (already done with .env)
- [ ] Set up firewall rules (allow only necessary ports)
- [ ] Enable SSL/TLS for API access
- [ ] Regularly update dependencies
- [ ] Monitor logs for suspicious activity
- [ ] Set up automated backups for database
- [ ] Use a reverse proxy (Nginx/Apache)
- [ ] Implement rate limiting
- [ ] Set up monitoring and alerting

## Monitoring

### Check Service Health

```bash
# Create a health check script
cat > check_health.sh << 'EOF'
#!/bin/bash
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo "✓ Service is healthy"
    exit 0
else
    echo "✗ Service is unhealthy"
    exit 1
fi
EOF

chmod +x check_health.sh

# Add to crontab for monitoring
crontab -e
# Add: */5 * * * * /path/to/check_health.sh
```

### Set Up Prometheus Monitoring (Optional)

Install prometheus-fastapi-instrumentator:
```bash
pip install prometheus-fastapi-instrumentator
```

Add to `app/main.py`:
```python
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
```

Access metrics at: `http://localhost:8000/metrics`

## Summary

Your Advisory Intelligence API is now:
- ✅ Running as a system service
- ✅ Automatically starts on boot
- ✅ Restarts automatically if it crashes
- ✅ Logs to files for debugging
- ✅ Accessible even after closing terminal

For production use, consider adding:
- Nginx reverse proxy
- SSL certificate
- Log rotation
- Monitoring and alerting
- Automated backups