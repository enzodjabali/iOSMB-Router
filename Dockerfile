# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o iosmb-router .

# Production stage
FROM alpine:latest

# Install ca-certificates for HTTPS and tzdata for timezone support
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/iosmb-router .

# Copy example rules file
COPY rules.example.yaml .

# Create volume for rules
VOLUME ["/app/rules"]

# Expose no ports (this is a client service)

# Run the application
CMD ["./iosmb-router"]
