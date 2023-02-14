package socks5

import (
	"fmt"
	"time"
)

type logWriter struct {
	description string
}

func newLogWriter(description string) *logWriter {
	lw := logWriter{description: description}
	return &lw
}

func (lw *logWriter) Write(bs []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format(time.RFC3339), " [", lw.description, "] ", string(bs))
}
