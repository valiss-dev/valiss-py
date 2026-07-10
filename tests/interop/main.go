// Interop harness for the Python port: exercises the Go valiss library
// against Python-produced credentials and vice versa. Driven by
// tests/test_interop.py.
//
//	go run . mint    # mint keys, tokens, and creds files; JSON to stdout
//	go run . verify  # verify a credential read as JSON from stdin
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss"
	"github.com/mikluko/valiss/creds"
)

type minted struct {
	OperatorPub  string `json:"operator_pub"`
	JTI          string `json:"jti"`
	AccountCreds string `json:"account_creds"`
	UserCreds    string `json:"user_creds"`
	BearerCreds  string `json:"bearer_creds"`
}

type credential struct {
	OperatorPub  string `json:"operator_pub"`
	JTI          string `json:"jti"`
	AccountToken string `json:"account_token"`
	UserToken    string `json:"user_token"`
	Timestamp    string `json:"timestamp"`
	Signature    string `json:"signature"`
}

type verified struct {
	Account string                     `json:"account"`
	User    string                     `json:"user,omitempty"`
	Bearer  bool                       `json:"bearer,omitempty"`
	UserExt map[string]json.RawMessage `json:"user_ext,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: interop mint|verify")
	}
	switch os.Args[1] {
	case "mint":
		mint()
	case "verify":
		verify()
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

	tok, err := valiss.Issue(operator, "acme", accountPub, valiss.WithTTL(time.Hour))
	check(err)
	claims, err := valiss.VerifyAccount(tok, operatorPub)
	check(err)
	userTok, err := valiss.IssueUser(account, "alice", userPub, valiss.WithTTL(time.Hour))
	check(err)
	bearerTok, err := valiss.IssueUser(account, "bob", bearerPub,
		valiss.WithTTL(15*time.Minute), valiss.WithBearer())
	check(err)

	out := minted{
		OperatorPub:  operatorPub,
		JTI:          claims.ID,
		AccountCreds: creds.Format(creds.Creds{AccountToken: tok, Seed: accountSeed}),
		UserCreds:    creds.Format(creds.Creds{AccountToken: tok, UserToken: userTok, Seed: userSeed}),
		BearerCreds:  creds.Format(creds.Creds{AccountToken: tok, UserToken: bearerTok}),
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

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
