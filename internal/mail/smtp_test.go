package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
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
			if !write("250-mail.clustr.internal") || !write("250 8BITMIME") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
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
