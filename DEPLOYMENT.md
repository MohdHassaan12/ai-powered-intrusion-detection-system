# 🚀 Autonomous SOC - Production Deployment Guide

Because AdvancedIDS performs deep packet inspection and actively manipulates raw network adapters, **it cannot be hosted on standard web platforms** (like Heroku, Vercel, or Render). 

It absolutely requires a dedicated Virtual Private Server (VPS) where you possess full `root` access. 

## 1. Required Infrastructure
* **Server**: Ubuntu 22.04 LTS (AWS EC2, DigitalOcean Droplet, Linode, etc.)
* **Minimum Specs**: 2GB RAM, 1 CPU Core (needed for Scapy & TensorFlow models)
* **Open Ports**: 80 (HTTP), 443 (HTTPS), 5001 (Internal Flask), and Decoy Ports (22, 23, 3306, 8080)

---

## 2. Server Provisioning & Initialization
Log into your new Ubuntu cloud server as `root` and run:

```bash
# Update OS and install packet sniffing dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv libpcap-dev tshark nginx
```

Clone your repository into the `/opt/` directory (the Linux standard for standalone enterprise applications):
```bash
cd /opt
sudo git clone <YOUR_GITHUB_REPO_URL> advanced-ids
cd advanced-ids
```

---

## 3. Python Virtual Environment
Initialize the Linux server's isolated Python environment:
```bash
sudo python3 -m venv venv
alias activate="source venv/bin/activate"
activate

# Install all frozen dependencies
sudo pip install -r requirements.txt
```

---

## 4. SystemD Daemon (Persistent Background Running)
To ensure the SOC platform starts automatically when the server turns on and automatically restarts if it crashes, you must register it as a native Linux service.

Create a new service configuration file:
`sudo nano /etc/systemd/system/advanced-ids.service`

Paste the following configuration:
```ini
[Unit]
Description=AdvancedIDS AI Security Operations Center
After=network.target

[Service]
User=root
WorkingDirectory=/opt/advanced-ids
Environment="PATH=/opt/advanced-ids/venv/bin"
# Run the application with absolute paths
ExecStart=/opt/advanced-ids/venv/bin/python3 app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the Engine:
```bash
sudo systemctl daemon-reload
sudo systemctl start advanced-ids
sudo systemctl enable advanced-ids
```

---

## 5. Nginx Reverse Proxy (Web Facing & SSL)
You don't want users accessing the unencrypted raw `5001` port. Nginx will route web traffic securely into your application.

First, set up your DNS. Go to your domain registrar (e.g., Cloudflare, Namecheap) and point an `A Record` for `tusharsec.com` to your VPS's Public IP Address.

Configure Nginx:
`sudo nano /etc/nginx/sites-available/advanced-ids`

```nginx
server {
    listen 80;
    server_name tusharsec.com www.tusharsec.com;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        
        # Extended timeouts for AI processing delays
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }
}
```

Activate the Nginx configuration:
```bash
sudo ln -s /etc/nginx/sites-available/advanced-ids /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 6. Securing with Let's Encrypt (Free SSL)
Finally, run Certbot to automatically encrypt your domain with `https://`:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d tusharsec.com -d www.tusharsec.com
```

Select the option to automatically redirect HTTP traffic to HTTPS.

**🎉 Congratulations. Your autonomous AI-powered Security Operations Center is now live and intercepting real-world web traffic!**
