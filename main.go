package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/fatih/color"
)

// Config structures
type Config struct {
	General    GeneralConfig    `toml:"general"`
	Ports      PortsConfig      `toml:"ports"`
	PerIPLimits PerIPConfig     `toml:"per_ip_limits"`
	PerFlowLimits PerFlowConfig `toml:"per_flow_limits"`
	Whitelist  WhitelistConfig  `toml:"whitelist"`
	Blacklist  BlacklistConfig  `toml:"blacklist"`
	Alerting   AlertingConfig   `toml:"alerting"`
}

type GeneralConfig struct {
	Interface string `toml:"interface"`
	XDPMode   string `toml:"xdp_mode"`
	Timeout   int    `toml:"timeout"`
}

type PortsConfig struct {
	PortsToProtect string `toml:"ports_to_protect"`
}

type PerIPConfig struct {
	PerIPPPSLimit    uint32 `toml:"per_ip_pps_limit"`
	PerIPSynPPSLimit uint32 `toml:"per_ip_syn_pps_limit"`
	PerIPUdpPPSLimit uint32 `toml:"per_ip_udp_pps_limit"`
	PerIPUdpBPSLimit uint64 `toml:"per_ip_udp_bps_limit"`
	PerIPBPSLimit    uint64 `toml:"per_ip_bps_limit"`
	Action           string `toml:"action"`
}

type PerFlowConfig struct {
	PerFlowPPSLimit    uint32 `toml:"per_flow_pps_limit"`
	PerFlowSynPPSLimit uint32 `toml:"per_flow_syn_pps_limit"`
	PerFlowUdpPPSLimit uint32 `toml:"per_flow_udp_pps_limit"`
	PerFlowUdpBPSLimit uint64 `toml:"per_flow_udp_bps_limit"`
	PerFlowBPSLimit    uint64 `toml:"per_flow_bps_limit"`
	Action             string `toml:"action"`
}

type WhitelistConfig struct {
	PreloadWhitelistFile string `toml:"preload_whitelist_file"`
}

type BlacklistConfig struct {
	PreloadBlacklistFile string `toml:"preload_blacklist_file"`
}

type AlertingConfig struct {
	Alert      string              `toml:"alert"`
	LogFile    string              `toml:"log_file"`
	WebhookURL string              `toml:"webhook_url"`
	Enable     AlertEnableConfig   `toml:"enable"`
}

type AlertEnableConfig struct {
	PerIPPPS        bool `toml:"per_ip_pps"`
	PerIPSynPPS     bool `toml:"per_ip_syn_pps"`
	PerIPUdpPPS     bool `toml:"per_ip_udp_pps"`
	PerIPUdpBPS     bool `toml:"per_ip_udp_bps"`
	PerIPBPS        bool `toml:"per_ip_bps"`
	PerFlowPPS      bool `toml:"per_flow_pps"`
	PerFlowSynPPS   bool `toml:"per_flow_syn_pps"`
	PerFlowUdpPPS   bool `toml:"per_flow_udp_pps"`
	PerFlowUdpBPS   bool `toml:"per_flow_udp_bps"`
	PerFlowBPS      bool `toml:"per_flow_bps"`
	Other           bool `toml:"other"`
}

// BPF structures
type BPFConfig struct {
	PerIPPPSLimit      uint32
	PerIPSynPPSLimit   uint32
	PerIPUdpPPSLimit   uint32
	PerIPUdpBPSLimit   uint64
	PerIPBPSLimit      uint64
	PerFlowPPSLimit    uint32
	PerFlowSynPPSLimit uint32
	PerFlowUdpPPSLimit uint32
	PerFlowUdpBPSLimit uint64
	PerFlowBPSLimit    uint64
	PerIPAction        uint8
	PerFlowAction      uint8
}

type CIDREntry struct {
	Addr uint32
	Mask uint32
}

type GlobalStats struct {
	PacketsPassed        uint64
	PacketsDropped       uint64
	PerIPPPSHits         uint64
	PerIPSynPPSHits      uint64
	PerIPUdpPPSHits      uint64
	PerIPUdpBPSHits      uint64
	PerIPBPSHits         uint64
	PerFlowPPSHits       uint64
	PerFlowSynPPSHits    uint64
	PerFlowUdpPPSHits    uint64
	PerFlowUdpBPSHits    uint64
	PerFlowBPSHits       uint64
	WhitelistHits        uint64
	BlacklistHits        uint64
	CurrentPPS           uint64
	CurrentBPS           uint64
	LastStatUpdate       uint64
}

var (
	timeoutFlag  = flag.Int("t", 0, "Timeout in seconds (0 = run indefinitely)")
	interfaceFlag = flag.String("i", "", "Network interface")
	modeFlag     = flag.String("d", "native", "XDP mode (native or generic)")
	configFlag   = flag.String("c", "config.toml", "Config file path")
)

func main() {
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configFlag)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override with CLI flags
	if *interfaceFlag != "" {
		config.General.Interface = *interfaceFlag
	}
	if *modeFlag != "" {
		config.General.XDPMode = *modeFlag
	}
	if *timeoutFlag > 0 {
		config.General.Timeout = *timeoutFlag
	}

	if config.General.Interface == "" {
		log.Fatal("Network interface must be specified")
	}

	// Initialize logging
	if err := initLogging(config.Alerting.LogFile); err != nil {
		log.Printf("Warning: Failed to initialize logging: %v", err)
	}

	// Load XDP program
	// Try multiple locations for the XDP object file
	xdpPaths := []string{
		"xdp_firewall.o",                                // Local build
		"/usr/local/lib/slice-xdp/xdp_firewall.o",      // System install
		"/etc/slice-xdp/xdp_firewall.o",                // Alternative location
	}
	
	var spec *ebpf.CollectionSpec
	var err error
	for _, path := range xdpPaths {
		spec, err = ebpf.LoadCollectionSpec(path)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Fatalf("Failed to load BPF spec (tried: %v): %v", xdpPaths, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_firewall_prog"]
	if prog == nil {
		log.Fatal("XDP program not found in object file")
	}

	// Attach to interface
	iface, err := net.InterfaceByName(config.General.Interface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", config.General.Interface, err)
	}

	var xdpFlags link.XDPAttachFlags
	if config.General.XDPMode == "native" {
		xdpFlags = link.XDPDriverMode
	} else {
		xdpFlags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	color.Green("✓ XDP program attached to %s in %s mode\n", config.General.Interface, config.General.XDPMode)

	// Configure maps
	if err := configureMaps(coll, config); err != nil {
		log.Fatalf("Failed to configure maps: %v", err)
	}

	color.Green("✓ Maps configured\n")

	// Load whitelist
	if config.Whitelist.PreloadWhitelistFile != "" {
		if err := loadWhitelist(coll.Maps["whitelist_map"], config.Whitelist.PreloadWhitelistFile); err != nil {
			log.Printf("Warning: Failed to load whitelist: %v", err)
		} else {
			color.Green("✓ Whitelist loaded\n")
		}
	}

	// Load blacklist
	if config.Blacklist.PreloadBlacklistFile != "" {
		if err := loadBlacklist(coll.Maps["blacklist_map"], config.Blacklist.PreloadBlacklistFile); err != nil {
			log.Printf("Warning: Failed to load blacklist: %v", err)
		} else {
			color.Green("✓ Blacklist loaded\n")
		}
	}

	// Start stats display
	stopChan := make(chan struct{})
	go displayStats(coll.Maps["stats_map"], coll.Maps["ip_map"], coll.Maps["flow_map"], stopChan)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	color.Cyan("\n=== Slice-XDP Firewall Running ===\n")
	color.Cyan("Press Ctrl+C to stop\n\n")

	// Wait for timeout or signal
	if config.General.Timeout > 0 {
		timer := time.NewTimer(time.Duration(config.General.Timeout) * time.Second)
		select {
		case <-timer.C:
			color.Yellow("\n✓ Timeout reached, detaching...\n")
		case <-sigChan:
			color.Yellow("\n✓ Signal received, detaching...\n")
		}
	} else {
		<-sigChan
		color.Yellow("\n✓ Signal received, detaching...\n")
	}

	close(stopChan)
	time.Sleep(100 * time.Millisecond) // Give stats display time to clean up

	color.Green("✓ Cleanup complete\n")
}

func loadConfig(path string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func initLogging(logFile string) error {
	if logFile == "" {
		return nil
	}

	dir := logFile[:strings.LastIndex(logFile, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	log.SetOutput(f)
	return nil
}

func configureMaps(coll *ebpf.Collection, config *Config) error {
	// Configure config map
	configMap := coll.Maps["config_map"]
	bpfConfig := BPFConfig{
		PerIPPPSLimit:      config.PerIPLimits.PerIPPPSLimit,
		PerIPSynPPSLimit:   config.PerIPLimits.PerIPSynPPSLimit,
		PerIPUdpPPSLimit:   config.PerIPLimits.PerIPUdpPPSLimit,
		PerIPUdpBPSLimit:   config.PerIPLimits.PerIPUdpBPSLimit,
		PerIPBPSLimit:      config.PerIPLimits.PerIPBPSLimit,
		PerFlowPPSLimit:    config.PerFlowLimits.PerFlowPPSLimit,
		PerFlowSynPPSLimit: config.PerFlowLimits.PerFlowSynPPSLimit,
		PerFlowUdpPPSLimit: config.PerFlowLimits.PerFlowUdpPPSLimit,
		PerFlowUdpBPSLimit: config.PerFlowLimits.PerFlowUdpBPSLimit,
		PerFlowBPSLimit:    config.PerFlowLimits.PerFlowBPSLimit,
		PerIPAction:        actionToByte(config.PerIPLimits.Action),
		PerFlowAction:      actionToByte(config.PerFlowLimits.Action),
	}

	key := uint32(0)
	if err := configMap.Put(&key, &bpfConfig); err != nil {
		return fmt.Errorf("failed to update config map: %w", err)
	}

	// Configure ports map
	portsMap := coll.Maps["ports_map"]
	ports, err := parsePorts(config.Ports.PortsToProtect)
	if err != nil {
		return fmt.Errorf("failed to parse ports: %w", err)
	}

	for i, port := range ports {
		key := uint32(i)
		portVal := uint16(port)
		if err := portsMap.Put(&key, &portVal); err != nil {
			return fmt.Errorf("failed to update ports map: %w", err)
		}
	}

	// Initialize stats map
	statsMap := coll.Maps["stats_map"]
	stats := GlobalStats{}
	key = 0
	if err := statsMap.Put(&key, &stats); err != nil {
		return fmt.Errorf("failed to initialize stats map: %w", err)
	}

	return nil
}

func actionToByte(action string) uint8 {
	if strings.ToLower(action) == "drop" {
		return 1
	}
	return 0
}

func parsePorts(portsStr string) ([]uint16, error) {
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" {
		return nil, fmt.Errorf("no ports specified")
	}

	var ports []uint16

	// Check for range
	if strings.Contains(portsStr, "-") {
		parts := strings.Split(portsStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range format")
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %w", err)
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %w", err)
		}

		if start > end || start < 1 || end > 65535 {
			return nil, fmt.Errorf("invalid port range")
		}

		for p := start; p <= end; p++ {
			ports = append(ports, uint16(p))
		}
	} else {
		// Multiple ports or single port
		portStrs := strings.Split(portsStr, ",")
		for _, ps := range portStrs {
			ps = strings.TrimSpace(ps)
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %w", err)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			ports = append(ports, uint16(port))
		}
	}

	return ports, nil
}

func loadWhitelist(m *ebpf.Map, filePath string) error {
	return loadIPList(m, filePath)
}

func loadBlacklist(m *ebpf.Map, filePath string) error {
	return loadIPList(m, filePath)
}

func loadIPList(m *ebpf.Map, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	index := uint32(0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseCIDR(line)
		if err != nil {
			log.Printf("Warning: Invalid entry %s: %v", line, err)
			continue
		}

		if err := m.Put(&index, &entry); err != nil {
			return fmt.Errorf("failed to add entry: %w", err)
		}
		index++
	}

	return nil
}

func parseCIDR(cidr string) (CIDREntry, error) {
	// Check if it's a CIDR or plain IP
	if !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return CIDREntry{}, err
	}

	addr := binary.LittleEndian.Uint32(ipnet.IP.To4())
	mask := binary.LittleEndian.Uint32(ipnet.Mask)

	return CIDREntry{
		Addr: addr & mask,
		Mask: mask,
	}, nil
}

func displayStats(statsMap, ipMap, flowMap *ebpf.Map, stopChan chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastStats GlobalStats
	firstRun := true

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			key := uint32(0)
			var stats GlobalStats

			if err := statsMap.Lookup(&key, &stats); err != nil {
				continue
			}

			// Calculate rates
			var pps, bps uint64
			if !firstRun {
				pps = stats.PacketsPassed + stats.PacketsDropped - lastStats.PacketsPassed - lastStats.PacketsDropped
				bps = stats.CurrentBPS
			}
			firstRun = false

			// Get map sizes
			ipMapSize := getMapSize(ipMap)
			flowMapSize := getMapSize(flowMap)

			// Clear screen and display stats
			fmt.Print("\033[H\033[2J")
			color.Cyan("=== Slice-XDP Firewall Stats ===\n\n")

			color.White("Traffic:\n")
			fmt.Printf("  Packets Passed:  %s\n", color.GreenString("%d", stats.PacketsPassed))
			fmt.Printf("  Packets Dropped: %s\n", color.RedString("%d", stats.PacketsDropped))
			fmt.Printf("  Current PPS:     %s\n", color.YellowString("%d", pps))
			fmt.Printf("  Current BPS:     %s\n", color.YellowString("%s", formatBytes(bps)))

			color.White("\nPer-IP Limit Hits:\n")
			fmt.Printf("  PPS:     %d\n", stats.PerIPPPSHits)
			fmt.Printf("  SYN PPS: %d\n", stats.PerIPSynPPSHits)
			fmt.Printf("  UDP PPS: %d\n", stats.PerIPUdpPPSHits)
			fmt.Printf("  UDP BPS: %d\n", stats.PerIPUdpBPSHits)
			fmt.Printf("  BPS:     %d\n", stats.PerIPBPSHits)

			color.White("\nPer-Flow Limit Hits:\n")
			fmt.Printf("  PPS:     %d\n", stats.PerFlowPPSHits)
			fmt.Printf("  SYN PPS: %d\n", stats.PerFlowSynPPSHits)
			fmt.Printf("  UDP PPS: %d\n", stats.PerFlowUdpPPSHits)
			fmt.Printf("  UDP BPS: %d\n", stats.PerFlowUdpBPSHits)
			fmt.Printf("  BPS:     %d\n", stats.PerFlowBPSHits)

			color.White("\nList Hits:\n")
			fmt.Printf("  Whitelist: %s\n", color.GreenString("%d", stats.WhitelistHits))
			fmt.Printf("  Blacklist: %s\n", color.RedString("%d", stats.BlacklistHits))

			color.White("\nMap Sizes:\n")
			fmt.Printf("  IP Map:   %d entries\n", ipMapSize)
			fmt.Printf("  Flow Map: %d entries\n", flowMapSize)

			lastStats = stats
		}
	}
}

func getMapSize(m *ebpf.Map) int {
	// This is an approximation as eBPF doesn't provide direct size
	// We'll iterate through the map (limited to prevent performance issues)
	count := 0
	iter := m.Iterate()
	var key, value []byte

	for iter.Next(&key, &value) && count < 10000 {
		count++
	}

	return count
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Discord webhook payload
type DiscordWebhook struct {
	Content string `json:"content"`
}

func sendDiscordAlert(webhookURL, message string) error {
	payload := DiscordWebhook{Content: message}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

