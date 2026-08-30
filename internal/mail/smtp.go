package mail

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

const smtpTimeout = 10 * time.Second

type SMTP struct {
	address      string
	hostname     string
	from         *netmail.Address
	envelopeFrom string
	auth         smtp.Auth
	tlsConfig    *tls.Config
}

type SMTPConfig struct {
	Address    string
	From       string
	Username   string
	Password   string
	ServerName string
	CAFile     string
}

func NewSMTP(address, from string) (*SMTP, error) {
	address = strings.TrimSpace(address)
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid SMTP address %q", address)
	}
	parsedFrom, err := netmail.ParseAddress(strings.TrimSpace(from))
	if err != nil || !validMailbox(parsedFrom.Address) {
		return nil, fmt.Errorf("invalid SMTP from address")
	}
	return &SMTP{
		address: address, hostname: host, from: parsedFrom,
		envelopeFrom: parsedFrom.Address,
	}, nil
}

// NewAuthenticatedSMTP configures an Internet SMTP submission endpoint. The
// connection must advertise STARTTLS and AUTH; credentials are never sent on a
// plaintext connection. CAFile is optional and augments the host's system trust
// store when a private relay is explicitly used.
func NewAuthenticatedSMTP(config SMTPConfig) (*SMTP, error) {
	address := strings.TrimSpace(config.Address)
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid SMTP address %q", address)
	}
	username := strings.TrimSpace(config.Username)
	if username == "" || config.Password == "" || strings.ContainsAny(username, "\r\n") {
		return nil, errors.New("authenticated SMTP requires a username and password")
	}
	serverName := strings.TrimSpace(config.ServerName)
	if serverName == "" {
		serverName = host
	}
	if net.ParseIP(serverName) != nil || strings.ContainsAny(serverName, "\r\n/:@") {
		return nil, errors.New("SMTP TLS server name must be a DNS hostname")
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system SMTP trust store: %w", err)
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caFile := strings.TrimSpace(config.CAFile); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read SMTP CA file: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("SMTP CA file did not contain a valid certificate")
		}
	}
	sender, err := NewSMTP(address, config.From)
	if err != nil {
		return nil, err
	}
	// net/smtp passes this name to Auth as the peer identity. Keep it aligned
	// with the DNS name verified by TLS even when the dial address is an IP.
	sender.hostname = serverName
	sender.auth = smtp.PlainAuth("", username, config.Password, serverName)
	sender.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    rootCAs,
	}
	return sender, nil
}

func (s *SMTP) Ping(ctx context.Context) error {
	client, conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := client.Noop(); err != nil {
		return fmt.Errorf("SMTP NOOP: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT: %w", err)
	}
	return nil
}

func (s *SMTP) SendPasswordReset(
	ctx context.Context,
	to string,
	code string,
	ttl time.Duration,
) error {
	if code == "" || strings.ContainsAny(code, "\r\n") {
		return errors.New("invalid reset code")
	}
	expiresMinutes := int(ttl.Round(time.Minute) / time.Minute)
	if expiresMinutes < 1 {
		expiresMinutes = 1
	}
	body := fmt.Sprintf(
		"Your Clixor password reset code is: %s\r\n\r\n"+
			"This code expires in %d minutes and can be used only once.\r\n"+
			"If you did not request this change, you can ignore this email.\r\n"+
			"Clixor will never ask you to send this code to anyone.\r\n",
		code, expiresMinutes,
	)
	return s.send(ctx, to, "Your Clixor password reset code", body)
}

func (s *SMTP) SendPasswordChanged(ctx context.Context, to string) error {
	body := "Your Clixor password was changed successfully.\r\n\r\n" +
		"All existing Clixor sessions were signed out. If you did not make this " +
		"change, contact support immediately.\r\n"
	return s.send(ctx, to, "Your Clixor password was changed", body)
}

func (s *SMTP) send(ctx context.Context, to, subject, body string) error {
	recipient, err := netmail.ParseAddress(strings.TrimSpace(to))
	if err != nil || !validMailbox(recipient.Address) {
		return errors.New("invalid mail recipient")
	}
	if subject == "" || strings.ContainsAny(subject, "\r\n") {
		return errors.New("invalid mail subject")
	}
	client, conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := client.Mail(s.envelopeFrom); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	messageID, err := randomMessageID()
	if err != nil {
		_ = writer.Close()
		return err
	}
	message := strings.Join([]string{
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"From: " + s.from.String(),
		"To: " + recipient.String(),
		"Subject: " + subject,
		"Message-ID: <" + messageID + "@atlanteanz.com>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"Auto-Submitted: auto-generated",
		"X-Auto-Response-Suppress: All",
		"",
		body,
	}, "\r\n")
	buffered := bufio.NewWriter(writer)
	if _, err := buffered.WriteString(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		_ = writer.Close()
		return fmt.Errorf("flush SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	// DATA completion includes the server's final acceptance response. Once it
	// succeeds, the local Postfix queue owns the message; a later QUIT/connection
	// error must not make callers discard the corresponding reset challenge.
	_ = client.Quit()
	return nil
}

func (s *SMTP) connect(ctx context.Context) (*smtp.Client, net.Conn, error) {
	dialer := &net.Dialer{Timeout: smtpTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, nil, fmt.Errorf("connect SMTP queue: %w", err)
	}
	deadline := time.Now().Add(smtpTimeout)
	if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("set SMTP deadline: %w", err)
	}
	client, err := smtp.NewClient(conn, s.hostname)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("open SMTP session: %w", err)
	}
	if s.tlsConfig != nil {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			client.Close()
			conn.Close()
			return nil, nil, errors.New("SMTP submission endpoint does not advertise STARTTLS")
		}
		if err := client.StartTLS(s.tlsConfig.Clone()); err != nil {
			client.Close()
			conn.Close()
			return nil, nil, fmt.Errorf("start SMTP TLS: %w", err)
		}
		if supported, _ := client.Extension("AUTH"); !supported {
			client.Close()
			conn.Close()
			return nil, nil, errors.New("SMTP submission endpoint does not advertise AUTH after TLS")
		}
		if err := client.Auth(s.auth); err != nil {
			client.Close()
			conn.Close()
			return nil, nil, fmt.Errorf("authenticate SMTP submission: %w", err)
		}
	}
	return client, conn, nil
}

func validMailbox(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\r\n") &&
		strings.Count(value, "@") == 1
}

func randomMessageID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate message ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}
