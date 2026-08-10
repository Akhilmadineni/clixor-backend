package auth

import "testing"

func TestPasswordHashAndVerify(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("password was not hashed")
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password was rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("incorrect password was accepted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	t.Parallel()
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
}
