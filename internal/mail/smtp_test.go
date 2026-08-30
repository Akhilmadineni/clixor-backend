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

type smtpTestServer struct {
	listener      net.Listener
	mu            sync.Mutex
	messages      []string
	errors        chan error
	dropAfterData bool
	tlsConfig     *tls.Config
	authUsername  string
	authPassword  string
}

func newSMTPTestServer(t *testing.T) *smtpTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &smtpTestServer{listener: listener, errors: make(chan error, 10)}
	go server.serve()
	t.Cleanup(func() { listener.Close() })
	return server
}

func newAuthenticatedSMTPTestServer(t *testing.T) (*smtpTestServer, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp.test"},
		DNSNames:     []string{"smtp.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
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
	server := newSMTPTestServer(t)
	server.tlsConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	server.authUsername = "smtp-user"
	server.authPassword = "smtp-password"
	return server, caFile
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
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	secure := false
	authenticated := s.tlsConfig == nil
	write := func(response string) bool {
		if _, err := writer.WriteString(response + "\r\n"); err != nil {
			s.errors <- err
			return false
		}
		if err := writer.Flush(); err != nil {
			s.errors <- err
			return false
		}
		return true
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
			if s.tlsConfig != nil && !secure {
				if !write("250-STARTTLS") || !write("250 8BITMIME") {
					return
				}
			} else if s.tlsConfig != nil {
				if !write("250-AUTH PLAIN") || !write("250 8BITMIME") {
					return
				}
			} else if !write("250 8BITMIME") {
				return
			}
		case command == "STARTTLS":
			if s.tlsConfig == nil || secure {
				_ = write("454 TLS unavailable")
				return
			}
			if !write("220 Ready to start TLS") {
				return
			}
			tlsConnection := tls.Server(connection, s.tlsConfig)
			if err := tlsConnection.Handshake(); err != nil {
				s.errors <- err
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
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			expected := "\x00" + s.authUsername + "\x00" + s.authPassword
			if err != nil || string(decoded) != expected {
				_ = write("535 5.7.8 Authentication failed")
				continue
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
					s.errors <- readErr
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				message.WriteString(dataLine)
			}
			s.mu.Lock()
			s.messages = append(s.messages, message.String())
			dropAfterData := s.dropAfterData
			s.mu.Unlock()
			if !write("250 2.0.0 queued") {
				return
			}
			if dropAfterData {
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

func TestSMTPQueuesResetAndConfirmationMessages(t *testing.T) {
	server := newSMTPTestServer(t)
	sender, err := NewSMTP(server.listener.Addr().String(), "Clixor <no-reply@atlanteanz.com>")
	if err != nil {
		t.Fatal(err)
	}
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
	select {
	case err := <-server.errors:
		t.Fatal(err)
	default:
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.messages) != 2 {
		t.Fatalf("queued messages = %d, want 2", len(server.messages))
	}
	if !strings.Contains(server.messages[0], "12345678") ||
		!strings.Contains(server.messages[0], "Content-Type: text/plain") ||
		!strings.Contains(server.messages[1], "password was changed successfully") {
		t.Fatalf("unexpected SMTP messages: %#v", server.messages)
	}
}

func TestSMTPRejectsHeaderInjection(t *testing.T) {
	if _, err := NewSMTP("127.0.0.1:25", "Clixor <no-reply@atlanteanz.com\r\nBcc: attacker@example.com>"); err == nil {
		t.Fatal("expected injected from address to be rejected")
	}
}

func TestSMTPTreatsDataAcceptanceAsQueueSuccess(t *testing.T) {
	server := newSMTPTestServer(t)
	server.mu.Lock()
	server.dropAfterData = true
	server.mu.Unlock()
	sender, err := NewSMTP(server.listener.Addr().String(), "Clixor <no-reply@atlanteanz.com>")
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendPasswordReset(
		context.Background(), "user@example.com", "12345678", 10*time.Minute,
	); err != nil {
		t.Fatalf("message accepted before connection close returned %v", err)
	}
}

func TestAuthenticatedSMTPRequiresTLSAndQueuesMessage(t *testing.T) {
	server, caFile := newAuthenticatedSMTPTestServer(t)
	sender, err := NewAuthenticatedSMTP(SMTPConfig{
		Address:  server.listener.Addr().String(),
		From:     "Clixor <no-reply@atlanteanz.com>",
		Username: "smtp-user", Password: "smtp-password",
		ServerName: "smtp.test", CAFile: caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sender.SendPasswordReset(ctx, "user@example.com", "12345678", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.messages) != 1 || !strings.Contains(server.messages[0], "12345678") {
		t.Fatalf("authenticated SMTP did not queue the reset message")
	}
}

func TestAuthenticatedSMTPFailsClosedWithoutSTARTTLS(t *testing.T) {
	server := newSMTPTestServer(t)
	sender, err := NewAuthenticatedSMTP(SMTPConfig{
		Address:  server.listener.Addr().String(),
		From:     "Clixor <no-reply@atlanteanz.com>",
		Username: "smtp-user", Password: "smtp-password", ServerName: "smtp.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plaintext SMTP endpoint returned %v, want STARTTLS failure", err)
	}
}

func TestAuthenticatedSMTPRequiresCredentialsAndDNSIdentity(t *testing.T) {
	for _, config := range []SMTPConfig{
		{Address: "smtp.example:587", From: "no-reply@example.com"},
		{Address: "smtp.example:587", From: "no-reply@example.com", Username: "user", Password: "password", ServerName: "127.0.0.1"},
	} {
		if _, err := NewAuthenticatedSMTP(config); err == nil {
			t.Fatalf("unsafe authenticated SMTP configuration was accepted: %+v", config)
		}
	}
}
