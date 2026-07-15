// Interop harness for the Python port: exercises the Go valiss library
// against Python-produced credentials and vice versa. Driven by
// tests/test_interop.py.
//
//	go run . mint            # mint keys, tokens, and creds files; JSON to stdout
//	go run . verify          # verify a request credential read as JSON from stdin
//	go run . verify_message  # verify a message token read as JSON from stdin
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

type minted struct {
	OperatorPub     string `json:"operator_pub"`
	JTI             string `json:"jti"`
	AccountCreds    string `json:"account_creds"`
	UserCreds       string `json:"user_creds"`
	BearerCreds     string `json:"bearer_creds"`
	MessageToken    string `json:"message_token"`
	MessageAudience string `json:"message_audience"`
	MessagePayload  string `json:"message_payload"`
}

type credential struct {
	OperatorPub  string `json:"operator_pub"`
	JTI          string `json:"jti"`
	AccountToken string `json:"account_token"`
	UserToken    string `json:"user_token"`
	Timestamp    string `json:"timestamp"`
	Signature    string `json:"signature"`
	Context      string `json:"context"`
	Nonce        string `json:"nonce"`
}

type verified struct {
	Account string                     `json:"account"`
	User    string                     `json:"user,omitempty"`
	Bearer  bool                       `json:"bearer,omitempty"`
	UserExt map[string]json.RawMessage `json:"user_ext,omitempty"`
}

// message is a Python-minted message token plus the bindings Go should
// enforce against it.
type message struct {
	OperatorPub string `json:"operator_pub"`
	Token       string `json:"token"`
	Audience    string `json:"audience"`
	Payload     string `json:"payload"`
}

type verifiedMessage struct {
	Subject  string `json:"subject"`
	Audience string `json:"audience"`
	Checksum string `json:"checksum"`
	Account  string `json:"account"`
	User     string `json:"user"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: interop mint|verify|verify_message")
	}
	switch os.Args[1] {
	case "mint":
		mint()
	case "verify":
		verify()
	case "verify_message":
		verifyMessage()
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func mint() {
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	accountSeed, err := account.Seed()
	check(err)
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)
	bearerUser, err := nkeys.CreateUser()
	check(err)
	bearerPub, err := bearerUser.PublicKey()
	check(err)

	tok, err := valiss.IssueAccount(operator, accountPub, valiss.WithName("acme"), valiss.WithTTL(time.Hour))
	check(err)
	claims, err := valiss.VerifyAccount(tok, operatorPub)
	check(err)
	userTok, err := valiss.IssueUser(account, userPub, valiss.WithName("alice"), valiss.WithTTL(time.Hour))
	check(err)
	bearerTok, err := valiss.IssueUser(account, bearerPub,
		valiss.WithName("bob"), valiss.WithTTL(15*time.Minute), valiss.WithBearer())
	check(err)

	// A message token minted by the same user key, embedding the provenance
	// chain, bound to an audience and a payload checksum.
	payload := "hello world"
	audience := "https://api.example.com/ingest"
	msgTok, err := valiss.IssueMessage(user,
		valiss.WithChain(tok, userTok),
		valiss.WithAudience(audience),
		valiss.WithChecksum(valiss.Checksum([]byte(payload))),
		valiss.WithTTL(valiss.DefaultMessageTTL))
	check(err)

	out := minted{
		OperatorPub:     operatorPub,
		JTI:             claims.ID,
		AccountCreds:    creds.Format(creds.Creds{AccountToken: tok, Seed: accountSeed}),
		UserCreds:       creds.Format(creds.Creds{AccountToken: tok, UserToken: userTok, Seed: userSeed}),
		BearerCreds:     creds.Format(creds.Creds{AccountToken: tok, UserToken: bearerTok}),
		MessageToken:    msgTok,
		MessageAudience: audience,
		MessagePayload:  payload,
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}

func verify() {
	var in credential
	check(json.NewDecoder(os.Stdin).Decode(&in))

	verifier := valiss.NewVerifier(in.OperatorPub, valiss.NewStaticAllowlist(in.JTI))
	id, err := verifier.VerifyRequest(valiss.Request{
		AccountToken: in.AccountToken,
		UserToken:    in.UserToken,
		Timestamp:    in.Timestamp,
		Signature:    in.Signature,
		Context:      []byte(in.Context),
		Nonce:        in.Nonce,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := verified{Account: id.Account.Name}
	if id.User != nil {
		out.User = id.User.Name
		out.Bearer = id.User.Bearer
		out.UserExt = id.User.Ext
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}

func verifyMessage() {
	var in message
	check(json.NewDecoder(os.Stdin).Decode(&in))

	opts := []valiss.VerifyMessageOption{}
	if in.Audience != "" {
		opts = append(opts, valiss.ExpectAudience(in.Audience))
	}
	if in.Payload != "" {
		opts = append(opts, valiss.WithPayload([]byte(in.Payload)))
	}
	mc, err := valiss.VerifyMessage(in.Token, in.OperatorPub, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := verifiedMessage{
		Subject:  mc.Subject,
		Audience: mc.Audience,
		Checksum: mc.Checksum,
		Account:  mc.Account.Name,
		User:     mc.User.Name,
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
