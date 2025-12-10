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
	Type                string   `yaml:"type"` // "redirect", "auto_reply", or "auto_reply_after_silence"
	FromSender          string   `yaml:"from_sender"`
	ToReceivers         []string `yaml:"to_receivers,omitempty"`
	ReplyText           string   `yaml:"reply_text,omitempty"`
	SilenceDurationSecs int      `yaml:"silence_duration_secs,omitempty"` // Time in seconds before auto-reply triggers
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
	conn                *websocket.Conn
	config              Config
	rules               Rules
	lastMessageTimeMap  map[string]time.Time      // Tracks last message time per sender (in-memory only)
	autoReplyStatusMap  map[string]bool           // Tracks if auto-reply was already sent
)

func main() {
	log.Println("iOSMB-Router starting...")

	// Configure timezone from environment variable
	configureTimezone()

	// Initialize tracking maps
	lastMessageTimeMap = make(map[string]time.Time)
	autoReplyStatusMap = make(map[string]bool)

	// Load configuration from environment or config file
	loadConfig()

	// Load rules
	if err := loadRules(config.RulesFile); err != nil {
		log.Fatalf("Failed to load rules: %v", err)
	}

	log.Printf("Loaded %d rules from %s", len(rules.Rules), config.RulesFile)

	// Connect to WebSocket server
	connectToServer()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down gracefully...")
	
	if conn != nil {
		conn.Close()
	}
}

func configureTimezone() {
	// Get timezone from environment variable (default: UTC)
	tzName := getEnv("TZ", "UTC")
	
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		log.Printf("Warning: Invalid timezone '%s', using UTC: %v", tzName, err)
		loc = time.UTC
	}
	
	// Set the local timezone for the application
	time.Local = loc
	log.Printf("Timezone set to: %s", loc.String())
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

	log.Printf("Server: %s:%d (SSL: %v)", config.ServerIP, config.ServerPort, config.SSL)
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

func connectToServer() {
	protocol := "ws"
	if config.SSL {
		protocol = "wss"
	}

	// iOSMB server expects authentication as query parameter
	url := fmt.Sprintf("%s://%s:%d?auth=%s", protocol, config.ServerIP, config.ServerPort, config.Password)
	log.Printf("Connecting to %s://%s:%d...", protocol, config.ServerIP, config.ServerPort)

	var err error
	conn, _, err = websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	log.Println("Connected to iOSMB server")

	// Start listening for messages
	go listenForMessages()

	// Keep connection alive
	go keepAlive()
}

func listenForMessages() {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			time.Sleep(5 * time.Second)
			connectToServer()
			return
		}

		var wsMsg WSMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			log.Printf("Failed to parse message: %v", err)
			continue
		}

		// Log all WebSocket actions
		log.Printf("Received action: %s", wsMsg.Action)

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
		log.Printf("Failed to parse message data: %v", err)
		return
	}

	// Check if we have message data
	if len(msgData.Message) == 0 {
		log.Printf("No message in data")
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
		log.Printf("Skipping own message")
		// Update last conversation time when you send a message
		lastMessageTimeMap[senderID] = time.Now()
		// Reset auto-reply status when you send a message (conversation resumed)
		autoReplyStatusMap[senderID] = false
		return
	}

	// Log every incoming message with sender details
	log.Printf("[NEW MESSAGE] From: %s | Text: %s | ChatID: %s | Type: %s", 
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
		log.Printf("Redirecting to %s", receiver)

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
	log.Printf("Auto-replying to %s", msg.Author)

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
		log.Printf("Auto-reply already sent to %s during this silence period", msg.Author)
		return
	}

	// Try to get last conversation time from in-memory map first
	lastTime, exists := lastMessageTimeMap[senderID]
	
	if !exists {
		// Not in memory, try to fetch from server
		log.Printf("First message from %s in this session, fetching message history from server", msg.Author)
		serverLastTime, err := getLastMessageTimeFromServer(msg.ChatID)
		if err != nil {
			log.Printf("Warning: Could not fetch message history: %v", err)
			log.Printf("Skipping auto-reply for first message (cannot verify conversation history)")
			// Don't send auto-reply if we can't verify the silence period
			// This prevents sending unwanted auto-replies after restart
			return
		}
		lastTime = serverLastTime
		log.Printf("Retrieved last message time from server: %s", lastTime.Format("2006-01-02 15:04:05"))
	}
	
	// Calculate time since last conversation
	timeSinceLastMsg := time.Since(lastTime)

	requiredSilence := time.Duration(rule.SilenceDurationSecs) * time.Second
	log.Printf("Time since last message from %s: %v (required: %v)", 
		msg.Author, timeSinceLastMsg, requiredSilence)

	// Check if enough time has passed
	if timeSinceLastMsg >= requiredSilence {
		log.Printf("Auto-replying to %s after %v of silence", msg.Author, timeSinceLastMsg)

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
		log.Printf("Not enough silence time for %s, skipping auto-reply", msg.Author)
	}
}

func getLastMessageTimeFromServer(chatID string) (time.Time, error) {
	protocol := "http"
	if config.SSL {
		protocol = "https"
	}
	
	// Try to get messages for this chat - limit to last few messages to find the most recent
	url := fmt.Sprintf("%s://%s:%d/getMessages?chatId=%s&limit=10", protocol, config.ServerIP, config.ServerPort, chatID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", config.Password)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	var messages []HistoricalMessage
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return time.Time{}, fmt.Errorf("decode response: %w", err)
	}

	if len(messages) == 0 {
		return time.Time{}, fmt.Errorf("no messages found for chat")
	}

	// Find the most recent message (highest timestamp)
	var mostRecent int64 = 0
	for _, msg := range messages {
		if msg.Date > mostRecent {
			mostRecent = msg.Date
		}
	}

	// Convert from milliseconds to time.Time
	return time.Unix(0, mostRecent*int64(time.Millisecond)), nil
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
		log.Printf("❌ Failed to marshal message: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("❌ Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", config.Password)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Server returned error: %d", resp.StatusCode)
		return
	}

	log.Printf("Message sent successfully")
}

func keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Printf("Ping failed: %v", err)
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
