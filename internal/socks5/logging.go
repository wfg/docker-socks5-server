package socks5

import (
	"fmt"
	"log"
	"os"
)

type Logger struct {
	*log.Logger
	description string
	debug       bool
}

func NewLogger(description string, debug bool) *Logger {
	return &Logger{
		Logger:      log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds|log.LUTC|log.Lshortfile),
		description: description,
		debug:       debug,
	}
}

func (l *Logger) Printf(format string, v ...interface{}) {
	l.Output(2, fmt.Sprintf("- "+l.description+" - INFO - "+format, v...))
}

func (l *Logger) Debugf(format string, v ...any) {
	if l.debug {
		l.Output(2, fmt.Sprintf("- "+l.description+" - DEBU - "+format, v...))
	}
}
