package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v2"
)


type SuspiciousPattern struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
}

type Config struct {
	Patterns []SuspiciousPattern `yaml:"suspicious_patterns"`
}

type DiscordConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type WhitelistConfig struct {
	IPs     []string `yaml:"ips"`
	Domains []string `yaml:"domains"`
}

type IpsPortscConfig struct {
	Targets []string `yaml:"targets"`
}


const pidFile = "/tmp/monitor.pid"


func loadPatterns(filename string) ([]SuspiciousPattern, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	return config.Patterns, err
}


func loadDiscordWebhook(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	var config DiscordConfig
	err = yaml.Unmarshal(data, &config)
	return config.WebhookURL, err
}


func loadWhitelist(filename string) (WhitelistConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return WhitelistConfig{}, err
	}
	var config WhitelistConfig
	err = yaml.Unmarshal(data, &config)
	return config, err
}


func loadIpsPortsc(filename string) (IpsPortscConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return IpsPortscConfig{}, err
	}
	var config IpsPortscConfig
	err = yaml.Unmarshal(data, &config)
	return config, err
}


func getServerInfo() (string, string, string) {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	localIP := getLocalIP()
	return hostname, username, localIP
}


func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "Desconhecido"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "Desconhecido"
}


func isSuspicious(payload string, patterns []SuspiciousPattern) (bool, string) {
	for _, p := range patterns {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(p.Pattern)) {
			return true, p.Description
		}
	}
	return false, ""
}


func isWhitelisted(ip string, domain string, whitelist WhitelistConfig) bool {
	
	for _, whitelistedIP := range whitelist.IPs {
		if ip == whitelistedIP {
			return true
		}
	}

	
	for _, whitelistedDomain := range whitelist.Domains {
		if domain == whitelistedDomain {
			return true
		}
	}

	return false
}


func sendDiscordAlert(webhookURL, message string) {
	payload := map[string]string{"content": message}
	jsonData, _ := json.Marshal(payload)
	_, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Erro ao enviar alerta para o Discord:", err)
	}
}


func portscan(target string) []int {
	var openPorts []int
	for port := 1; port <= 65535; port++ {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			fmt.Printf("🔍 Porta %d aberta em %s\n", port, target)
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts
}


func monitorPort(port int, patterns []SuspiciousPattern, webhookURL, hostname, username, localIP string, whitelist WhitelistConfig) {
	device := "lo"
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp port %d", port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("🚀 Monitorando tráfego na porta %d...\n", port)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			payload := string(applicationLayer.Payload())
			srcIP := packet.NetworkLayer().NetworkFlow().Src().String()

			
			if !isWhitelisted(srcIP, "", whitelist) {
				if suspicious, desc := isSuspicious(payload, patterns); suspicious {
					alertMessage := fmt.Sprintf(
						"⚠️ **ALERTA!** Tráfego suspeito detectado!\n"+
							"🔍 **Motivo:** %s\n"+
							"📄 **Conteúdo suspeito:** ```%s```\n"+
							"💻 **Servidor:** %s\n"+
							"👤 **Usuário:** %s\n"+
							"🌍 **IP Local:** %s\n"+
							"🔢 **Porta:** %d",
						desc, payload, hostname, username, localIP, port,
					)

					fmt.Println(alertMessage)
					sendDiscordAlert(webhookURL, alertMessage)
				}
			} else {
				fmt.Printf("💚 IP %s na whitelist, ignorando.\n", srcIP)
			}
		}
	}
}


func startDaemon() {
	cmd := exec.Command(os.Args[0], "-daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	err := cmd.Start()
	if err != nil {
		log.Fatalf("Erro ao iniciar o daemon: %v", err)
	}

	fmt.Printf("✅ Monitor started in background with PID %d\n", cmd.Process.Pid)
	ioutil.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
}


func stopDaemon() {
	data, err := ioutil.ReadFile(pidFile)
	if err != nil {
		log.Fatalf("Erro ao ler PID do processo: %v", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		log.Fatalf("Erro ao converter PID: %v", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		log.Fatalf("Erro ao encontrar processo: %v", err)
	}

	err = process.Kill()
	if err != nil {
		log.Fatalf("Erro ao parar o processo: %v", err)
	}

	fmt.Println("🛑 Monitor stopped successfully.")
	os.Remove(pidFile)
}


func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-start":
			startDaemon()
			return
		case "-stop":
			stopDaemon()
			return
		case "-daemon":
			break 
		default:
			fmt.Println("Uso: go run script.go -start | -stop")
			return
		}
	}

	
	patterns, err := loadPatterns("config/patterns.yaml")
	if err != nil {
		log.Fatalf("Erro ao carregar padrões: %v", err)
	}

	webhookURL, err := loadDiscordWebhook("config/apidiscord.yaml")
	if err != nil {
		log.Fatalf("Erro ao carregar webhook do Discord: %v", err)
	}

	whitelist, err := loadWhitelist("config/whitelist.yaml")
	if err != nil {
		log.Fatalf("Erro ao carregar whitelist: %v", err)
	}

	ipsPortsc, err := loadIpsPortsc("config/ipsportsc.yaml")
	if err != nil {
		log.Fatalf("Erro ao carregar ipsportsc: %v", err)
	}

	hostname, username, localIP := getServerInfo()

	
	for _, target := range ipsPortsc.Targets {
		openPorts := portscan(target)
		for _, port := range openPorts {
			go monitorPort(port, patterns, webhookURL, hostname, username, localIP, whitelist)
		}
	}

	select {} 
}
