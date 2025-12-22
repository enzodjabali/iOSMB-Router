package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/mail"
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
	Type                string   `yaml:"type"` // "redirect", "auto_reply", "auto_reply_after_silence", "scheduled_message", or "redirect_emails"
	FromSender          string   `yaml:"from_sender,omitempty"`
	ToReceivers         []string `yaml:"to_receivers,omitempty"`
	ReplyText           string   `yaml:"reply_text,omitempty"`
	SilenceDurationSecs int      `yaml:"silence_duration_secs,omitempty"` // Time in seconds before auto-reply triggers
	Schedule            string   `yaml:"schedule,omitempty"`              // Cron expression for scheduled messages
	MessageText         string   `yaml:"message_text,omitempty"`          // Text for scheduled messages
	// Email-specific fields
	EmailServer       string `yaml:"email_server,omitempty"`        // IMAP server address (e.g., "imap.gmail.com:993")
	Username          string `yaml:"username,omitempty"`            // Email username/address
	Password          string `yaml:"password,omitempty"`            // Email password
	CheckIntervalSecs int    `yaml:"check_interval_secs,omitempty"` // How often to check for new emails (default: 60)
	Enabled           bool   `yaml:"enabled"`
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
	emailMonitors      map[string]chan bool // Tracks email monitoring goroutines for shutdown
)

// Email monitoring functions
func initializeEmailMonitors() {
	emailMonitors = make(map[string]chan bool)

	emailCount := 0
	for idx, rule := range rules.Rules {
		if !rule.Enabled || rule.Type != "redirect_emails" {
			continue
		}

		// Validate required fields
		if rule.EmailServer == "" {
			log.Printf("WARNING: Email rule '%s' missing email_server, skipping", rule.Name)
			continue
		}
		if rule.Username == "" {
			log.Printf("WARNING: Email rule '%s' missing username, skipping", rule.Name)
			continue
		}
		if rule.Password == "" {
			log.Printf("WARNING: Email rule '%s' missing password, skipping", rule.Name)
			continue
		}
		if len(rule.ToReceivers) == 0 {
			log.Printf("WARNING: Email rule '%s' has no receivers, skipping", rule.Name)
			continue
		}

		// Default check interval to 60 seconds if not specified
		checkInterval := rule.CheckIntervalSecs
		if checkInterval <= 0 {
			checkInterval = 60
		}

		// Create stop channel for this monitor
		stopChan := make(chan bool)
		emailMonitors[rule.Name] = stopChan

		// Start monitoring in a goroutine
		go monitorEmailAccount(rule, checkInterval, stopChan)

		log.Printf("INFO: Started email monitor '%s' for %s (checking every %d seconds, filtering from: %s)",
			rule.Name, rule.Username, checkInterval, rule.FromSender)
		emailCount++

		// Small delay to avoid overwhelming the server
		time.Sleep(time.Duration(idx) * time.Second)
	}

	if emailCount > 0 {
		log.Printf("INFO: Started %d email monitors", emailCount)
	} else {
		log.Println("INFO: No email monitors configured")
	}
}

func monitorEmailAccount(rule Rule, checkIntervalSecs int, stopChan chan bool) {
	ticker := time.NewTicker(time.Duration(checkIntervalSecs) * time.Second)
	defer ticker.Stop()

	// Track last check time to only get new emails
	lastCheckTime := time.Now()

	for {
		select {
		case <-stopChan:
			log.Printf("INFO: Stopping email monitor for '%s'", rule.Name)
			return
		case <-ticker.C:
			checkForNewEmails(rule, lastCheckTime)
			lastCheckTime = time.Now()
		}
	}
}

func checkForNewEmails(rule Rule, since time.Time) {
	// Connect to IMAP server
	client, err := imapclient.DialTLS(rule.EmailServer, nil)
	if err != nil {
		log.Printf("ERROR: Failed to connect to email server %s: %v", rule.EmailServer, err)
		return
	}
	defer client.Close()

	// Login
	if err := client.Login(rule.Username, rule.Password).Wait(); err != nil {
		log.Printf("ERROR: Failed to login to email account %s: %v", rule.Username, err)
		return
	}
	defer client.Logout()

	// Select INBOX
	mailbox, err := client.Select("INBOX", nil).Wait()
	if err != nil {
		log.Printf("ERROR: Failed to select INBOX: %v", err)
		return
	}

	// If no messages, return early
	if mailbox.NumMessages == 0 {
		return
	}

	// Search for unseen messages
	searchCriteria := &imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}

	// If we have a specific sender filter, add it
	if rule.FromSender != "" {
		searchCriteria.Header = []imap.SearchCriteriaHeaderField{
			{Key: "From", Value: rule.FromSender},
		}
	}

	searchData, err := client.Search(searchCriteria, nil).Wait()
	if err != nil {
		log.Printf("ERROR: Failed to search emails: %v", err)
		return
	}

	// Check if we have any messages
	seqNums := searchData.AllSeqNums()
	if len(seqNums) == 0 {
		return
	}

	// Create sequence set from the numbers using the helper function
	seqSet := imap.SeqSetNum(seqNums...)

	// Fetch the messages (without Peek so they get marked as read)
	fetchOptions := &imap.FetchOptions{
		Envelope: true,
		BodySection: []*imap.FetchItemBodySection{
			{}, // Not using Peek, so messages will be marked as read
		},
	}

	fetchCmd := client.Fetch(seqSet, fetchOptions)
	defer fetchCmd.Close()

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}

		// Collect message data into buffer
		msgBuffer, err := msg.Collect()
		if err != nil {
			log.Printf("ERROR: Failed to collect message: %v", err)
			continue
		}

		processEmailMessage(rule, msgBuffer)
	}

	if err := fetchCmd.Close(); err != nil {
		log.Printf("ERROR: Fetch error: %v", err)
	}
}

func processEmailMessage(rule Rule, msg *imapclient.FetchMessageBuffer) {
	// Check if we have envelope data
	if msg.Envelope == nil {
		log.Printf("WARNING: Message has no envelope data")
		return
	}

	env := msg.Envelope

	// Extract sender email
	var fromEmail string
	if len(env.From) > 0 {
		fromEmail = env.From[0].Addr()
	}

	// Extract subject
	subject := env.Subject

	// Try to get email body
	emailBody := ""
	for _, bodySection := range msg.BodySection {
		// Get the body bytes directly
		bodyBytes := bodySection.Bytes

		if len(bodyBytes) > 0 {
			// Try to parse as mail message
			mr, err := mail.CreateReader(bytes.NewReader(bodyBytes))
			if err == nil {
				for {
					part, err := mr.NextPart()
					if err != nil {
						break
					}
					if part.Header.Get("Content-Type") != "" &&
						(strings.Contains(part.Header.Get("Content-Type"), "text/plain") ||
							strings.Contains(part.Header.Get("Content-Type"), "text/html")) {
						bodyContent, err := io.ReadAll(part.Body)
						if err == nil {
							emailBody = string(bodyContent)
							break
						}
					}
				}
			}

			// If we couldn't parse it, use raw body
			if emailBody == "" {
				emailBody = string(bodyBytes)
			}
		}
		break // Only process first body section
	}

	// Truncate body if too long (SMS has limits)
	maxBodyLength := 300
	if len(emailBody) > maxBodyLength {
		emailBody = emailBody[:maxBodyLength] + "..."
	}

	// Clean up body (remove extra whitespace)
	emailBody = strings.TrimSpace(emailBody)

	log.Printf("INFO: [NEW EMAIL] From: %s | Subject: %s", fromEmail, subject)

	// Forward to all receivers via SMS
	for _, receiver := range rule.ToReceivers {
		messageText := fmt.Sprintf("Email from %s\n\nSubject: %s\n\n%s",
			fromEmail, subject, emailBody)

		outMsg := OutgoingMessage{
			Address:     receiver,
			Text:        messageText,
			Subject:     "",
			Attachments: []interface{}{},
		}

		sendMessage(outMsg)
		log.Printf("INFO: Forwarded email to %s", receiver)
	}
}

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

	// Initialize email monitors for redirect_emails rules
	initializeEmailMonitors()

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

	// Stop all email monitors
	for name, stopChan := range emailMonitors {
		log.Printf("INFO: Stopping email monitor: %s", name)
		stopChan <- true
		close(stopChan)
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
