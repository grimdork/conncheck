package conncheck_test

import (
	"testing"

	"github.com/grimdork/conncheck"
)

func TestChecker(t *testing.T) {
	ch, err := conncheck.NewChecker("https://github.com")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("Checker created.")
	err = ch.CheckConn()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("TCP connection OK.")
	err = ch.CheckTLSConn()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("TLS connection OK.")
	res, err := ch.GetHTTP()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	res.Body.Close()
	t.Logf("HTTP response: %d (%s)", res.StatusCode, res.Status)
}
