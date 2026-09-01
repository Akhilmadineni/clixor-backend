package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type smtpTestServerConfig struct {
	tlsConfig     *tls.Config
	implicitTLS   bool
	advertiseAuth bool
	authUsername  string
	authPassword  string
	dropAfterData bool
	stallGreeting bool
	advertiseTLS  bool
}

type smtpTestServer struct {
	listener net.Listener
	config   smtpTestServerConfig
	mu       sync.Mutex
	messages []string
	errors   chan error
}

func newSMTPTestServer(t *testing.T, config smtpTestServerConfig) *smtpTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Publish the complete immutable configuration before starting the accept
	// goroutine. This ordering keeps the TLS fixture race-free.
	server := &smtpTestServer{
		listener: listener, config: config, errors: make(chan error, 20),
	}
	go server.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func newAuthenticatedSMTPTestServer(
	t *testing.T,
	implicitTLS bool,
) (*smtpTestServer, string) {
	t.Helper()
	tlsConfig, caFile := smtpTestTLSConfig(t)
	return newSMTPTestServer(t, smtpTestServerConfig{
		tlsConfig: tlsConfig, implicitTLS: implicitTLS,
		advertiseTLS: !implicitTLS, advertiseAuth: true,
		authUsername: "smtp-user", authPassword: "smtp-password",
	}), caFile
}

func smtpTestTLSConfig(t *testing.T) (*tls.Config, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "smtp.test"}, DNSNames: []string{"smtp.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "smtp-ca.pem")
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
	}, caFile
}

func (s *smtpTestServer) serve() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(connection)
	}
}

func (s *smtpTestServer) handle(connection net.Conn) {
	defer connection.Close()
	if s.config.stallGreeting {
		buffer := make([]byte, 1)
		_, _ = connection.Read(buffer)
		return
	}
	secure := false
	if s.config.implicitTLS {
		tlsConnection := tls.Server(connection, s.config.tlsConfig)
		if err := tlsConnection.Handshake(); err != nil {
			return
		}
		connection = tlsConnection
		secure = true
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	authenticated := false
	write := func(response string) bool {
		if _, err := writer.WriteString(response + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !write("220 mail.clustr.internal ESMTP") {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			if !write("250-mail.clustr.internal") {
				return
			}
			switch {
			case !secure && s.config.advertiseTLS:
				if !write("250-STARTTLS") || !write("250 8BITMIME") {
					return
				}
			case secure && s.config.advertiseAuth:
				if !write("250-AUTH PLAIN") || !write("250 8BITMIME") {
					return
				}
			default:
				if !write("250 8BITMIME") {
					return
				}
			}
		case command == "STARTTLS":
			if s.config.tlsConfig == nil || secure || !s.config.advertiseTLS {
				_ = write("454 TLS unavailable")
				return
			}
			if !write("220 Ready to start TLS") {
				return
			}
			tlsConnection := tls.Server(connection, s.config.tlsConfig)
			if err := tlsConnection.Handshake(); err != nil {
				return
			}
			connection = tlsConnection
			reader = bufio.NewReader(connection)
			writer = bufio.NewWriter(connection)
			secure = true
		case strings.HasPrefix(command, "AUTH PLAIN "):
			if !secure {
				_ = write("538 Encryption required")
				return
			}
			encoded := strings.TrimSpace(line[len("AUTH PLAIN "):])
			decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
			expected := "\x00" + s.config.authUsername + "\x00" + s.config.authPassword
			if decodeErr != nil || string(decoded) != expected {
				_ = write("535 5.7.8 Authentication failed")
				return
			}
			authenticated = true
			if !write("235 2.7.0 Authentication successful") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
			if !authenticated {
				_ = write("530 Authentication required")
				return
			}
			if !write("250 2.1.0 OK") {
				return
			}
		case command == "DATA":
			if !write("354 End data with <CR><LF>.<CR><LF>") {
				return
			}
			var message strings.Builder
			for {
				dataLine, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				message.WriteString(dataLine)
			}
			s.mu.Lock()
			s.messages = append(s.messages, message.String())
			s.mu.Unlock()
			if !write("250 2.0.0 queued") || s.config.dropAfterData {
				return
			}
		case command == "NOOP":
			if !write("250 2.0.0 OK") {
				return
			}
		case command == "QUIT":
			_ = write("221 2.0.0 bye")
			return
		default:
			s.errors <- fmt.Errorf("unexpected SMTP command %q", command)
			_ = write("500 unsupported")
			return
		}
	}
}

func authenticatedTestSender(
	t *testing.T,
	server *smtpTestServer,
	caFile, transport string,
) *SMTP {
	t.Helper()
	sender, err := NewAuthenticatedSMTP(SMTPConfig{
		Address: server.listener.Addr().String(), From: "Clixor <no-reply@atlanteanz.com>",
		Username: "smtp-user", Password: "smtp-password",
		ServerName: "smtp.test", CAFile: caFile, Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

func TestAuthenticatedSMTPQueuesMessagesWithBothTLSModes(t *testing.T) {
	for _, transport := range []string{SMTPTransportStartTLS, SMTPTransportImplicitTLS} {
		t.Run(transport, func(t *testing.T) {
			server, caFile := newAuthenticatedSMTPTestServer(
				t, transport == SMTPTransportImplicitTLS,
			)
			sender := authenticatedTestSender(t, server, caFile, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := sender.Ping(ctx); err != nil {
				t.Fatal(err)
			}
			if err := sender.SendPasswordReset(ctx, "user@example.com", "12345678", 10*time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := sender.SendPasswordChanged(ctx, "user@example.com"); err != nil {
				t.Fatal(err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.messages) != 2 || !strings.Contains(server.messages[0], "12345678") ||
				!strings.Contains(server.messages[0], "Content-Type: text/plain") ||
				!strings.Contains(server.messages[1], "password was changed successfully") {
				t.Fatalf("unexpected queued message count/content: %d", len(server.messages))
			}
		})
	}
}

func TestAuthenticatedSMTPFailsClosedWithoutSTARTTLS(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	sender := authenticatedTestSender(t, server, "", SMTPTransportStartTLS)
	if err := sender.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plaintext SMTP endpoint returned %v, want STARTTLS failure", err)
	}
}

func TestAuthenticatedSMTPRejectsUntrustedOrWrongIdentity(t *testing.T) {
	server, caFile := newAuthenticatedSMTPTestServer(t, false)
	for name, mutate := range map[string]func(*SMTPConfig){
		"untrusted":  func(config *SMTPConfig) { config.CAFile = "" },
		"wrong-host": func(config *SMTPConfig) { config.ServerName = "other.test" },
	} {
		t.Run(name, func(t *testing.T) {
			config := SMTPConfig{
				Address: server.listener.Addr().String(), From: "no-reply@atlanteanz.com",
				Username: "smtp-user", Password: "smtp-password", ServerName: "smtp.test",
				CAFile: caFile, Transport: SMTPTransportStartTLS,
			}
			mutate(&config)
			sender, err := NewAuthenticatedSMTP(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.Ping(context.Background()); err == nil {
				t.Fatal("SMTP accepted an unverified TLS peer")
			}
		})
	}
}

func TestAuthenticatedSMTPRequiresTLS12AndAuth(t *testing.T) {
	t.Run("tls-version", func(t *testing.T) {
		tlsConfig, caFile := smtpTestTLSConfig(t)
		tlsConfig.MaxVersion = tls.VersionTLS11
		server := newSMTPTestServer(t, smtpTestServerConfig{
			tlsConfig: tlsConfig, advertiseTLS: true, advertiseAuth: true,
			authUsername: "smtp-user", authPassword: "smtp-password",
		})
		sender := authenticatedTestSender(t, server, caFile, SMTPTransportStartTLS)
		if err := sender.Ping(context.Background()); err == nil {
			t.Fatal("SMTP accepted TLS below 1.2")
		}
	})
	t.Run("missing-auth", func(t *testing.T) {
		tlsConfig, caFile := smtpTestTLSConfig(t)
		server := newSMTPTestServer(t, smtpTestServerConfig{
			tlsConfig: tlsConfig, advertiseTLS: true,
		})
		sender := authenticatedTestSender(t, server, caFile, SMTPTransportStartTLS)
		if err := sender.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "AUTH") {
			t.Fatalf("SMTP without AUTH returned %v", err)
		}
	})
}

func TestAuthenticatedSMTPErrorNeverContainsCredentials(t *testing.T) {
	server, caFile := newAuthenticatedSMTPTestServer(t, false)
	config := SMTPConfig{
		Address: server.listener.Addr().String(), From: "no-reply@atlanteanz.com",
		Username: "highly-secret-user", Password: "highly-secret-password",
		ServerName: "smtp.test", CAFile: caFile, Transport: SMTPTransportStartTLS,
	}
	sender, err := NewAuthenticatedSMTP(config)
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Ping(context.Background())
	if err == nil {
		t.Fatal("wrong credentials unexpectedly authenticated")
	}
	if strings.Contains(err.Error(), config.Username) || strings.Contains(err.Error(), config.Password) {
		t.Fatal("SMTP error exposed credentials")
	}
}

func TestAuthenticatedSMTPInvalidAddressNeverEchoesConfiguration(t *testing.T) {
	secretAddress := "smtp-user:smtp-password@bad-address"
	_, err := NewAuthenticatedSMTP(SMTPConfig{
		Address: secretAddress, From: "no-reply@atlanteanz.com",
		Username: "smtp-user", Password: "smtp-password",
		ServerName: "smtp.example.com", Transport: SMTPTransportImplicitTLS,
	})
	if err == nil {
		t.Fatal("invalid SMTP address was accepted")
	}
	if strings.Contains(err.Error(), secretAddress) || strings.Contains(err.Error(), "smtp-password") {
		t.Fatalf("SMTP configuration error exposed address content: %v", err)
	}
}

func TestAuthenticatedSMTPCancellationInterruptsPostDialGreeting(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{stallGreeting: true})
	sender := authenticatedTestSender(t, server, "", SMTPTransportStartTLS)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- sender.Ping(ctx) }()
	time.Sleep(50 * time.Millisecond)
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled SMTP greeting unexpectedly succeeded")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("post-dial cancellation took %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("post-dial SMTP operation ignored context cancellation")
	}
}

func TestAuthenticatedSMTPRejectsInjectionAndUnsafeConfiguration(t *testing.T) {
	base := SMTPConfig{
		Address: "127.0.0.1:587", From: "no-reply@atlanteanz.com",
		Username: "user", Password: "password", ServerName: "smtp.example.com",
		Transport: SMTPTransportStartTLS,
	}
	invalid := []SMTPConfig{
		{Address: base.Address, From: base.From, Transport: base.Transport},
		{Address: base.Address, From: base.From, Username: "user", Password: "password", ServerName: "127.0.0.1", Transport: base.Transport},
		{Address: base.Address, From: base.From, Username: "user", Password: "password", ServerName: base.ServerName},
		{Address: base.Address, From: "Clixor <no-reply@atlanteanz.com\r\nBcc: attacker@example.com>", Username: "user", Password: "password", ServerName: base.ServerName, Transport: base.Transport},
		{Address: base.Address, From: base.From, Username: "user\x00attacker", Password: "password", ServerName: base.ServerName, Transport: base.Transport},
	}
	for index, config := range invalid {
		if _, err := NewAuthenticatedSMTP(config); err == nil {
			t.Fatalf("unsafe SMTP configuration %d was accepted", index)
		}
	}
	sender, err := NewAuthenticatedSMTP(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendPasswordReset(
		context.Background(), "victim@example.com\r\nBcc: attacker@example.com", "12345678", 10*time.Minute,
	); err == nil {
		t.Fatal("injected recipient was accepted")
	}
	if err := sender.SendPasswordReset(
		context.Background(), "victim@example.com", "12345678\r\nBcc: attacker@example.com", 10*time.Minute,
	); err == nil {
		t.Fatal("injected reset code was accepted")
	}
}

func TestSMTPTreatsDataAcceptanceAsQueueSuccess(t *testing.T) {
	tlsConfig, caFile := smtpTestTLSConfig(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{
		tlsConfig: tlsConfig, advertiseTLS: true, advertiseAuth: true,
		authUsername: "smtp-user", authPassword: "smtp-password", dropAfterData: true,
	})
	sender := authenticatedTestSender(t, server, caFile, SMTPTransportStartTLS)
	if err := sender.SendPasswordReset(
		context.Background(), "user@example.com", "12345678", 10*time.Minute,
	); err != nil {
		t.Fatalf("message accepted before connection close returned %v", err)
	}
}
