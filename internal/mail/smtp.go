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
	"strconv"
	"strings"
	"time"
)

const smtpTimeout = 10 * time.Second

const (
	SMTPTransportStartTLS    = "starttls"
	SMTPTransportImplicitTLS = "implicit_tls"
)

type SMTP struct {
	address      string
	hostname     string
	from         *netmail.Address
	envelopeFrom string
	auth         smtp.Auth
	tlsConfig    *tls.Config
	transport    string
}

type SMTPConfig struct {
	Address    string
	From       string
	Username   string
	Password   string
	ServerName string
	CAFile     string
	Transport  string
}

func newSMTP(address, from string) (*SMTP, error) {
	address, host, err := parseSMTPAddress(address)
	if err != nil {
		return nil, err
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

// NewAuthenticatedSMTP configures an Internet SMTP submission endpoint using
// either mandatory STARTTLS or implicit TLS. AUTH is required only after the
// peer certificate and hostname are verified. CAFile optionally augments the
// host trust store for an explicitly configured private relay.
func NewAuthenticatedSMTP(config SMTPConfig) (*SMTP, error) {
	address, host, err := parseSMTPAddress(config.Address)
	if err != nil {
		return nil, err
	}
	username := strings.TrimSpace(config.Username)
	if username == "" || config.Password == "" ||
		strings.ContainsAny(username, "\x00\r\n") || strings.Contains(config.Password, "\x00") {
		return nil, errors.New("authenticated SMTP requires a username and password")
	}
	transport := strings.TrimSpace(config.Transport)
	if transport != SMTPTransportStartTLS && transport != SMTPTransportImplicitTLS {
		return nil, errors.New("SMTP transport must be starttls or implicit_tls")
	}
	serverName := strings.TrimSpace(config.ServerName)
	if serverName == "" {
		serverName = host
	}
	if !validDNSHostname(serverName) {
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
	sender, err := newSMTP(address, config.From)
	if err != nil {
		return nil, err
	}
	// net/smtp passes this name to Auth as the peer identity. Keep it aligned
	// with the DNS name verified by TLS even when the dial address is an IP.
	sender.hostname = serverName
	sender.auth = smtp.PlainAuth("", username, config.Password, serverName)
	sender.transport = transport
	sender.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    rootCAs,
	}
	return sender, nil
}

func parseSMTPAddress(value string) (string, string, error) {
	address := strings.TrimSpace(value)
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || strings.TrimSpace(host) == "" || portErr != nil || port < 1 || port > 65535 ||
		(net.ParseIP(host) == nil && !validDNSHostname(host)) {
		return "", "", errors.New("invalid SMTP address")
	}
	return address, host, nil
}

func (s *SMTP) Ping(ctx context.Context) error {
	session, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer session.close()
	if err := session.client.Noop(); err != nil {
		return fmt.Errorf("SMTP NOOP: %w", err)
	}
	if err := session.client.Quit(); err != nil {
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
	session, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer session.close()
	client := session.client
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
	// succeeds, the submission provider owns the message; a later QUIT/connection
	// error must not make callers discard the corresponding reset challenge.
	_ = client.Quit()
	return nil
}

type smtpSession struct {
	client     *smtp.Client
	connection net.Conn
	stopCancel func() bool
}

func (s *smtpSession) close() {
	if s.stopCancel != nil {
		s.stopCancel()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.connection != nil {
		_ = s.connection.Close()
	}
}

func (s *SMTP) connect(ctx context.Context) (*smtpSession, error) {
	dialer := &net.Dialer{Timeout: smtpTimeout}
	rawConnection, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, fmt.Errorf("connect SMTP submission: %w", err)
	}
	session := &smtpSession{connection: rawConnection}
	session.stopCancel = context.AfterFunc(ctx, func() {
		// net/smtp has no context-aware command methods. Expiring the socket
		// deadline interrupts greeting, TLS, AUTH, and DATA promptly after the
		// caller cancels instead of retaining a worker for the full hard timeout.
		_ = rawConnection.SetDeadline(time.Now())
	})
	fail := func(err error) (*smtpSession, error) {
		session.close()
		return nil, err
	}
	deadline := time.Now().Add(smtpTimeout)
	if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	if err := rawConnection.SetDeadline(deadline); err != nil {
		return fail(fmt.Errorf("set SMTP deadline: %w", err))
	}
	connection := rawConnection
	if s.transport == SMTPTransportImplicitTLS {
		tlsConnection := tls.Client(rawConnection, s.tlsConfig.Clone())
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return fail(fmt.Errorf("open implicit SMTP TLS: %w", err))
		}
		connection = tlsConnection
		session.connection = tlsConnection
	}
	client, err := smtp.NewClient(connection, s.hostname)
	if err != nil {
		return fail(fmt.Errorf("open SMTP session: %w", err))
	}
	session.client = client
	if s.transport == SMTPTransportStartTLS {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			return fail(errors.New("SMTP submission endpoint does not advertise STARTTLS"))
		}
		if err := client.StartTLS(s.tlsConfig.Clone()); err != nil {
			return fail(fmt.Errorf("start SMTP TLS: %w", err))
		}
	}
	if supported, _ := client.Extension("AUTH"); !supported {
		return fail(errors.New("SMTP submission endpoint does not advertise AUTH after TLS"))
	}
	if err := client.Auth(s.auth); err != nil {
		return fail(fmt.Errorf("authenticate SMTP submission: %w", err))
	}
	return session, nil
}

func validMailbox(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\r\n") &&
		strings.Count(value, "@") == 1
}

func validDNSHostname(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil ||
		strings.ContainsAny(value, "\x00\r\n/:@ ") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func randomMessageID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate message ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}
