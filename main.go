package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	ServerIP   string `yaml:"server_ip"`
	ServerPort int    `yaml:"server_port"`
	Password   string `yaml:"password"`
	SSL        bool   `yaml:"ssl"`
	RulesFile  string `yaml:"rules_file"`
}

// Rules configuration structure
type Rules struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Name                string   `yaml:"name"`
	Type                string   `yaml:"type"` // "redirect", "auto_reply", "auto_reply_after_silence", or "scheduled_message"
	FromSender          string   `yaml:"from_sender,omitempty"`
	ToReceivers         []string `yaml:"to_receivers,omitempty"`
	ReplyText           string   `yaml:"reply_text,omitempty"`
	SilenceDurationSecs int      `yaml:"silence_duration_secs,omitempty"` // Time in seconds before auto-reply triggers
	Schedule            string   `yaml:"schedule,omitempty"`              // Cron expression for scheduled messages
	MessageText         string   `yaml:"message_text,omitempty"`          // Text for scheduled messages
	Enabled             bool     `yaml:"enabled"`
}

// WebSocket message structures
type WSMessage struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

type MessageData struct {
	Chat    []ChatInfo    `json:"chat"`
	Message []MessageInfo `json:"message"`
}

type ChatInfo struct {
	Address  string `json:"address"`
	Author   string `json:"author"`
	Text     string `json:"text"`
	PersonID string `json:"personId"`
}

type MessageInfo struct {
	Author      string        `json:"author"`
	ChatID      string        `json:"chatId"`
	Text        string        `json:"text"`
	Sender      int           `json:"sender"` // 0 = received, 1 = sent by you
	PersonID    string        `json:"personId"`
	Attachments []interface{} `json:"attachments"`
	Type        string        `json:"type"`
	Date        int64         `json:"date,omitempty"` // Unix timestamp in milliseconds
}

type OutgoingMessage struct {
	Address     string        `json:"address"`
	Text        string        `json:"text"`
	Subject     string        `json:"subject"`
	Attachments []interface{} `json:"attachments"`
}

// Message history structures
type HistoricalMessage struct {
	Date   int64  `json:"date"`   // Unix timestamp in milliseconds
	Sender int    `json:"sender"` // 0 = received, 1 = sent by you
	Text   string `json:"text"`
}

var (
	conn               *websocket.Conn
	config             Config
	rules              Rules
	lastMessageTimeMap map[string]time.Time // Tracks last message time per sender (in-memory only)
	autoReplyStatusMap map[string]bool      // Tracks if auto-reply was already sent
	cronScheduler      *cron.Cron           // Cron scheduler for scheduled messages
)

func main() {
	log.Println("INFO: iOSMB-Router starting...")

	// Configure timezone from environment variable
	configureTimezone()

	// Initialize tracking maps
	lastMessageTimeMap = make(map[string]time.Time)
	autoReplyStatusMap = make(map[string]bool)

	// Load configuration from environment or config file
	loadConfig()

	// Load rules
	if err := loadRules(config.RulesFile); err != nil {
		log.Fatalf("ERROR: Failed to load rules: %v", err)
	}

	log.Printf("INFO: Loaded %d rules from %s", len(rules.Rules), config.RulesFile)

	// Initialize and start cron scheduler for scheduled messages
	initializeScheduledMessages()

	// Connect to WebSocket server
	connectToServer()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("INFO: Shutting down gracefully...")
	
	// Stop cron scheduler
	if cronScheduler != nil {
		cronScheduler.Stop()
	}
	
	if conn != nil {
		conn.Close()
	}
}

func configureTimezone() {
	// Get timezone from environment variable (default: UTC)
	tzName := getEnv("TZ", "UTC")
	
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		log.Printf("WARNING: Invalid timezone '%s', using UTC: %v", tzName, err)
		loc = time.UTC
	}
	
	// Set the local timezone for the application
	time.Local = loc
	log.Printf("INFO: Timezone set to: %s", loc.String())
}

func loadConfig() {
	// Priority: Environment variables > default values
	config = Config{
		ServerIP:   getEnv("IOSMB_SERVER_IP", "192.168.1.100"),
		ServerPort: getEnvInt("IOSMB_SERVER_PORT", 8180),
		Password:   getEnv("IOSMB_SERVER_PASSWORD", ""),
		SSL:        getEnvBool("IOSMB_SERVER_SSL", false),
		RulesFile:  getEnv("IOSMB_RULES_FILE", "rules.yaml"),
	}

	log.Printf("INFO: Server: %s:%d (SSL: %v)", config.ServerIP, config.ServerPort, config.SSL)
}

func loadRules(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	return nil
}

func initializeScheduledMessages() {
	// Create cron scheduler with seconds precision
	cronScheduler = cron.New(cron.WithSeconds())

	scheduledCount := 0
	for _, rule := range rules.Rules {
		if !rule.Enabled || rule.Type != "scheduled_message" {
			continue
		}

		if rule.Schedule == "" {
			log.Printf("WARNING: Scheduled message rule '%s' has no schedule, skipping", rule.Name)
			continue
		}

		if rule.MessageText == "" {
			log.Printf("WARNING: Scheduled message rule '%s' has no message text, skipping", rule.Name)
			continue
		}

		if len(rule.ToReceivers) == 0 {
			log.Printf("WARNING: Scheduled message rule '%s' has no receivers, skipping", rule.Name)
			continue
		}

		// Capture variables for closure
		ruleName := rule.Name
		receivers := rule.ToReceivers
		messageText := rule.MessageText

		// Add scheduled job
		_, err := cronScheduler.AddFunc(rule.Schedule, func() {
			log.Printf("INFO: Executing scheduled message: %s", ruleName)
			for _, receiver := range receivers {
				outMsg := OutgoingMessage{
					Address:     receiver,
					Text:        messageText,
					Subject:     "",
					Attachments: []interface{}{},
				}
				sendMessage(outMsg)
			}
		})

		if err != nil {
			log.Printf("ERROR: Failed to schedule rule '%s': %v", rule.Name, err)
			continue
		}

		log.Printf("INFO: Scheduled message '%s' with cron: %s (receivers: %v)", 
			rule.Name, rule.Schedule, rule.ToReceivers)
		scheduledCount++
	}

	if scheduledCount > 0 {
		cronScheduler.Start()
		log.Printf("INFO: Started cron scheduler with %d scheduled messages", scheduledCount)
	} else {
		log.Println("INFO: No scheduled messages configured")
	}
}

func connectToServer() {
	protocol := "ws"
	if config.SSL {
		protocol = "wss"
	}

	// iOSMB server expects authentication as query parameter
	url := fmt.Sprintf("%s://%s:%d?auth=%s", protocol, config.ServerIP, config.ServerPort, config.Password)
	log.Printf("INFO: Connecting to %s://%s:%d...", protocol, config.ServerIP, config.ServerPort)

	var err error
	conn, _, err = websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Fatalf("ERROR: Failed to connect: %v", err)
	}

	log.Println("INFO: Connected to iOSMB server")

	// Start listening for messages
	go listenForMessages()

	// Keep connection alive
	go keepAlive()
}

func listenForMessages() {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("ERROR: Read error: %v", err)
			time.Sleep(5 * time.Second)
			connectToServer()
			return
		}

		var wsMsg WSMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			log.Printf("ERROR: Failed to parse message: %v", err)
			continue
		}

		// Log all WebSocket actions
		log.Printf("INFO: Received action: %s", wsMsg.Action)

		// Process incoming messages (handle both camelCase and snake_case)
		if wsMsg.Action == "newMessage" || wsMsg.Action == "new_message" {
			processMessage(wsMsg.Data)
		}
	}
}

func processMessage(data interface{}) {
	// Convert data to MessageData
	msgBytes, _ := json.Marshal(data)
	var msgData MessageData
	if err := json.Unmarshal(msgBytes, &msgData); err != nil {
		log.Printf("ERROR: Failed to parse message data: %v", err)
		return
	}

	// Check if we have message data
	if len(msgData.Message) == 0 {
		log.Printf("INFO: No message in data")
		return
	}

	msg := msgData.Message[0]
	
	// Get sender identifier (prefer ChatID, fallback to Author)
	senderID := msg.ChatID
	if senderID == "" {
		senderID = msg.Author
	}
	
	// Skip messages sent by you (sender == 1)
	if msg.Sender == 1 {
		log.Printf("INFO: Skipping own message")
		// Update last conversation time when you send a message
		lastMessageTimeMap[senderID] = time.Now()
		// Reset auto-reply status when you send a message (conversation resumed)
		autoReplyStatusMap[senderID] = false
		return
	}

	// Log every incoming message with sender details
	log.Printf("INFO: [NEW MESSAGE] From: %s | Text: %s | ChatID: %s | Type: %s", 
		msg.Author, 
		truncate(msg.Text, 50), 
		msg.ChatID,
		msg.Type)

	// Apply rules
	for _, rule := range rules.Rules {
		if !rule.Enabled {
			continue
		}

		// Match against author name, personId, or chatId
		if matchesSender(msg.Author, rule.FromSender) || 
		   matchesSender(msg.PersonID, rule.FromSender) ||
		   matchesSender(msg.ChatID, rule.FromSender) {
			log.Printf("Rule matched: %s", rule.Name)

			switch rule.Type {
			case "redirect":
				handleRedirect(msg, rule)
			case "auto_reply":
				handleAutoReply(msg, rule)
			case "auto_reply_after_silence":
				handleAutoReplyAfterSilence(msg, rule, senderID)
			default:
				log.Printf("Unknown rule type: %s", rule.Type)
			}
		}
	}

	// Update last conversation time AFTER processing rules
	// This ensures the next message can check the time properly
	lastMessageTimeMap[senderID] = time.Now()
}

func matchesSender(sender, pattern string) bool {
	// Simple case-insensitive matching
	// You can extend this with regex or more complex matching
	return strings.Contains(strings.ToLower(sender), strings.ToLower(pattern))
}

func handleRedirect(msg MessageInfo, rule Rule) {
	for _, receiver := range rule.ToReceivers {
		log.Printf("INFO: Redirecting to %s", receiver)

		outMsg := OutgoingMessage{
			Address:     receiver,
			Text:        fmt.Sprintf("Forwarded from %s:\n%s", msg.Author, msg.Text),
			Subject:     "",
			Attachments: []interface{}{},
		}

		sendMessage(outMsg)
	}
}

func handleAutoReply(msg MessageInfo, rule Rule) {
	log.Printf("INFO: Auto-replying to %s", msg.Author)
	outMsg := OutgoingMessage{
		Address:     msg.ChatID,
		Text:        rule.ReplyText,
		Subject:     "",
		Attachments: []interface{}{},
	}

	sendMessage(outMsg)
}

func handleAutoReplyAfterSilence(msg MessageInfo, rule Rule, senderID string) {
	// Check if auto-reply was already sent during this silence period
	if autoReplyStatusMap[senderID] {
		log.Printf("INFO: Auto-reply already sent to %s during this silence period", msg.Author)
		return
	}

	// Get last message time from in-memory map
	lastTime, exists := lastMessageTimeMap[senderID]
	
	if !exists {
		// First message from this sender - start tracking
		log.Printf("INFO: First message from %s in this session, starting to track conversation time", msg.Author)
		return
	}
	
	// Calculate time since last message (from either sender)
	timeSinceLastMsg := time.Since(lastTime)
	requiredSilence := time.Duration(rule.SilenceDurationSecs) * time.Second
	
	log.Printf("INFO: Time since last message from %s: %v (required: %v)", 
		msg.Author, timeSinceLastMsg, requiredSilence)

	// Check if enough time has passed
	if timeSinceLastMsg >= requiredSilence {
		log.Printf("INFO: Auto-replying to %s after %v of silence", msg.Author, timeSinceLastMsg)

		outMsg := OutgoingMessage{
			Address:     msg.ChatID,
			Text:        rule.ReplyText,
			Subject:     "",
			Attachments: []interface{}{},
		}

		sendMessage(outMsg)
		
		// Mark that auto-reply was sent for this silence period
		autoReplyStatusMap[senderID] = true
	} else {
		log.Printf("INFO: Not enough silence time for %s (missing %v), skipping auto-reply", 
			msg.Author, requiredSilence-timeSinceLastMsg)
	}
}

func sendMessage(msg OutgoingMessage) {
	// Use HTTP POST like the web client does
	protocol := "http"
	if config.SSL {
		protocol = "https"
	}
	
	url := fmt.Sprintf("%s://%s:%d/sendText", protocol, config.ServerIP, config.ServerPort)
	
	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("ERROR: Failed to marshal message: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("ERROR: Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", config.Password)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Server returned error: %d", resp.StatusCode)
		return
	}

	log.Printf("Message sent successfully")
}

func keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Printf("ERROR: Ping failed: %v", err)
			return
		}
	}
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
