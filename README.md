# iOSMB-Router

Automated message routing and auto-reply service for iOSMB (iOS Message Bridge). Create rules to forward messages from specific senders to multiple recipients or automatically reply to incoming messages.

## Features

- **Message Forwarding** - Redirect messages from specific senders to multiple recipients
- **Auto-Reply** - Automatically respond to messages based on sender
- **YAML Configuration** - Easy-to-read and modify rules
- **Real-time Processing** - Processes messages as they arrive via WebSocket
- **Docker Support** - Easy deployment with Docker and Docker Compose
- **Environment Variables** - Configure server connection without modifying code

## Quick Start

### Using Docker Compose (Recommended)

1. **Copy the environment file:**
   ```bash
   cd iOSMB-Router
   cp .env.example .env
   ```

2. **Edit `.env` with your iOSMB server details:**
   ```bash
   IOSMB_SERVER_IP=192.168.1.100
   IOSMB_SERVER_PORT=8180
   IOSMB_SERVER_PASSWORD=your-server-password
   IOSMB_SERVER_SSL=false
   ```

3. **Create your rules file:**
   ```bash
   cp rules.example.yaml rules.yaml
   # Edit rules.yaml with your custom rules
   ```

4. **Start the service:**
   ```bash
   docker-compose up -d
   ```

5. **View logs:**
   ```bash
   docker-compose logs -f
   ```

### Using Go Directly

1. **Install dependencies:**
   ```bash
   go mod download
   ```

2. **Create configuration:**
   ```bash
   cp .env.example .env
   cp rules.example.yaml rules.yaml
   # Edit both files
   ```

3. **Run the service:**
   ```bash
   source .env
   go run main.go
   ```

## Rules Configuration

Rules are defined in `rules.yaml` using a simple YAML format:

### Redirect Rule Example

Forward all messages from Netflix to multiple phone numbers:

```yaml
rules:
  - name: "Forward Netflix notifications"
    type: redirect
    from_sender: "Netflix"
    to_receivers:
      - "+33722335544"
      - "+33755442211"
    enabled: true
```

### Auto-Reply Rule Example

Automatically reply to a specific sender:

```yaml
rules:
  - name: "Auto reply to friend"
    type: auto_reply
    from_sender: "+33233556699"
    reply_text: "I will answer you shortly"
    enabled: true
```

### Auto-Reply After Silence Rule Example

Automatically reply only if there hasn't been a conversation for a specified time:

```yaml
rules:
  - name: "Auto reply after 1 hour of silence"
    type: auto_reply_after_silence
    from_sender: "+33611223344"
    reply_text: "I will reply you soon"
    silence_duration_secs: 3600  # 1 hour (3600s), 2h (7200s), 30min (1800s)
    enabled: true
```

**Note:** The silence tracking tracks BOTH incoming and outgoing messages in-memory. When either you or the sender messages, it updates the timer. After a restart, tracking begins fresh - the first message from each sender starts the timer, and the second message will trigger the auto-reply if the silence duration has elapsed.

### Scheduled Message Rule Example

Send messages automatically at specific times using cron syntax:

```yaml
rules:
  # Every day at 9:00 AM
  - name: "Daily morning reminder"
    type: scheduled_message
    schedule: "0 0 9 * * *"
    message_text: "Good morning! Don't forget your daily tasks."
    to_receivers:
      - "+33611223344"
      - "+33722335544"
    enabled: true

  # Every Saturday at 3:30 PM
  - name: "Weekly Saturday message"
    type: scheduled_message
    schedule: "0 30 15 * * 6"
    message_text: "Happy Saturday!"
    to_receivers:
      - "+33611223344"
    enabled: true

  # Every hour at 55 minutes
  - name: "Hourly reminder"
    type: scheduled_message
    schedule: "0 55 * * * *"
    message_text: "Hourly check-in"
    to_receivers:
      - "+33611223344"
    enabled: true
```

**Cron Format:** `second minute hour day month weekday`
- `*` = any value
- `*/15` = every 15 units
- `0 0 9 * * *` = Every day at 9:00:00 AM
- `0 30 15 * * 6` = Every Saturday at 3:30:00 PM
- `0 0 */2 * * *` = Every 2 hours
- `0 0 8-17 * * 1-5` = Every hour from 8 AM to 5 PM on weekdays

### Rule Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `name` | string | Yes | Descriptive name for the rule |
| `type` | string | Yes | Rule type: `redirect`, `auto_reply`, `auto_reply_after_silence`, or `scheduled_message` |
| `from_sender` | string | For redirect/auto_reply | Sender name or number to match (case-insensitive substring) |
| `to_receivers` | array | For redirect/scheduled | List of phone numbers to forward/send to |
| `reply_text` | string | For auto_reply | Text to send as automatic reply |
| `silence_duration_secs` | integer | For auto_reply_after_silence | Silence duration in seconds before auto-reply triggers |
| `schedule` | string | For scheduled_message | Cron expression (format: `sec min hour day month weekday`) |
| `message_text` | string | For scheduled_message | Text to send at scheduled times |
| `enabled` | boolean | Yes | Enable/disable the rule without deleting it |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IOSMB_SERVER_IP` | `192.168.1.100` | iOSMB server IP address |
| `IOSMB_SERVER_PORT` | `8180` | iOSMB server port |
| `IOSMB_SERVER_PASSWORD` | - | iOSMB server password |
| `IOSMB_SERVER_SSL` | `false` | Use WSS instead of WS |
| `IOSMB_RULES_FILE` | `rules.yaml` | Path to rules configuration file |
| `TZ` | `UTC` | Timezone for log timestamps (e.g., `Europe/Paris`, `America/New_York`) |

## How It Works

1. **Connects** to your iOSMB server via WebSocket (same connection as the web client)
2. **Authenticates** using the server password
3. **Listens** for incoming messages in real-time
4. **Matches** messages against your defined rules
5. **Executes** actions (forward or auto-reply) when rules match

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   iPhone    │ ──────> │ iOSMB Server│ ──────> │ iOSMB-Relay │
│  (Messages) │         │  (WebSocket)│         │   (Rules)   │
└─────────────┘         └─────────────┘         └─────────────┘
                                                        │
                                                        ▼
                                              ┌──────────────────┐
                                              │ Forward to phones│
                                              │  or Auto-reply   │
                                              └──────────────────┘
```

## Use Cases

### Forward Important Notifications
```yaml
- name: "Forward bank alerts"
  type: redirect
  from_sender: "Bank"
  to_receivers:
    - "+33600000001"  # Your work phone
    - "+33600000002"  # Your partner's phone
  enabled: true
```

### Out of Office Auto-Reply
```yaml
- name: "Vacation auto-reply"
  type: auto_reply
  from_sender: "work"  # Matches any sender with "work" in name
  reply_text: "I'm on vacation until Monday. For urgent matters, call +33600000000"
  enabled: true
```

### Emergency Contact Forwarding
```yaml
- name: "Forward urgent messages"
  type: redirect
  from_sender: "urgent"
  to_receivers:
    - "+33600000001"
  enabled: true
```

### Delivery Acknowledgment
```yaml
- name: "Confirm delivery notifications"
  type: auto_reply
  from_sender: "UPS"
  reply_text: "Thank you for the delivery update!"
  enabled: false
```

## Docker Production Deployment

For production with Docker Swarm:

```yaml
version: '3.9'

services:
  iosmb-router:
    image: ghcr.io/enzodjabali/iosmb-router:latest
    environment:
      - IOSMB_SERVER_IP=${IOSMB_SERVER_IP}
      - IOSMB_SERVER_PORT=${IOSMB_SERVER_PORT}
      - IOSMB_SERVER_PASSWORD=${IOSMB_SERVER_PASSWORD}
      - IOSMB_SERVER_SSL=${IOSMB_SERVER_SSL}
    configs:
      - source: relay_rules
        target: /app/rules.yaml
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

configs:
  relay_rules:
    file: ./rules.yaml
```

## Building from Source

```bash
# Clone the repository
cd iOSMB-Router

# Build binary
go build -o iosmb-router .

# Run
./iosmb-router
```

## Troubleshooting

### Connection Issues
- Verify `IOSMB_SERVER_IP` and `IOSMB_SERVER_PORT` are correct
- Ensure the iOSMB server is running and accessible
- Check if SSL is required (`IOSMB_SERVER_SSL=true`)

### Rules Not Matching
- The `from_sender` field uses case-insensitive substring matching
- Example: `"Netflix"` will match "netflix", "NETFLIX", "Netflix Support"
- Check logs to see incoming message details

### Messages Not Sending
- Verify phone numbers include country code (e.g., `+33...`)
- Check that the iOSMB server allows message sending
- View logs for error messages

## Logs

The service provides detailed logging:

```
iOSMB-Router starting...
Server: 192.168.1.100:8180 (SSL: false)
Loaded 5 rules from rules.yaml
Connecting to ws://192.168.1.100:8180...
Connected to iOSMB server
[NEW MESSAGE] From: Netflix | Text: Your payment was successful...
Rule matched: Forward Netflix notifications
Redirecting to +33722335544
Redirecting to +33755442211
Message sent successfully
```

## License

MIT License

## Credits

Part of the iOSMB (iOS Message Bridge) ecosystem.
