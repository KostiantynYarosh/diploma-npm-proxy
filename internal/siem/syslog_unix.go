//go:build !windows

package siem

import "log/syslog"

func dialSyslog(network, addr string) (syslogWriter, error) {
	w, err := syslog.Dial(network, addr, syslog.LOG_WARNING|syslog.LOG_DAEMON, "npm-proxy")
	if err != nil {
		return nil, err
	}
	return w, nil
}
