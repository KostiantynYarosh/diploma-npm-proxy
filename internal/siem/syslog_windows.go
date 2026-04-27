//go:build windows

package siem

import "fmt"

func dialSyslog(network, addr string) (syslogWriter, error) {
	return nil, fmt.Errorf("syslog not supported on Windows; use webhook mode")
}
