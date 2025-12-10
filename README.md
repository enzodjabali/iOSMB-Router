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

### Rule Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `name` | string | Yes | Descriptive name for the rule |
| `type` | string | Yes | Rule type: `redirect` or `auto_reply` |
| `from_sender` | string | Yes | Sender name or number to match (case-insensitive substring) |
| `to_receivers` | array | For redirect | List of phone numbers to forward to |
| `reply_text` | string | For auto_reply | Text to send as automatic reply |
| `enabled` | boolean | Yes | Enable/disable the rule without deleting it |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IOSMB_SERVER_IP` | `192.168.1.100` | iOSMB server IP address |
| `IOSMB_SERVER_PORT` | `8180` | iOSMB server port |
| `IOSMB_SERVER_PASSWORD` | - | iOSMB server password |
| `IOSMB_SERVER_SSL` | `false` | Use WSS instead of WS |
| `IOSMB_RULES_FILE` | `rules.yaml` | Path to rules configuration file |

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
