package tlsprobe

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// ParseEndpoint parses a "host" or "host:port" probe target, applying
// defaultPort when no port is given. Bracketed IPv6 literals such as "[::1]:443"
// and bare IPv6 literals are accepted. A scheme, path, query, fragment,
// wildcard, or control character is rejected, and a single trailing dot is
// removed so "example.com." and "example.com" name the same host.
func ParseEndpoint(value string, defaultPort int) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, errors.New("empty host")
	}
	if strings.Contains(value, "://") {
		return "", 0, errors.New("host must not include a scheme")
	}
	host, portText := value, ""
	switch {
	case strings.HasPrefix(value, "["):
		if strings.HasSuffix(value, "]") {
			host = value[1 : len(value)-1]
			break
		}
		parsedHost, parsedPort, err := net.SplitHostPort(value)
		if err != nil {
			return "", 0, fmt.Errorf("invalid host %q: %w", value, err)
		}
		host, portText = parsedHost, parsedPort
	case strings.Count(value, ":") == 1:
		parsedHost, parsedPort, err := net.SplitHostPort(value)
		if err != nil {
			return "", 0, fmt.Errorf("invalid host %q: %w", value, err)
		}
		host, portText = parsedHost, parsedPort
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	if strings.ContainsAny(host, " \t/?#@*") {
		return "", 0, fmt.Errorf("invalid host %q", host)
	}
	if strings.ContainsFunc(host, unicode.IsControl) {
		return "", 0, fmt.Errorf("invalid host %q", host)
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	if net.ParseIP(host) == nil {
		host = strings.ToLower(host)
		if strings.Contains(host, ":") {
			return "", 0, fmt.Errorf("invalid host %q", host)
		}
	} else {
		host = net.ParseIP(host).String()
	}
	port := defaultPort
	if portText != "" {
		parsed, err := strconv.Atoi(portText)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port %q", portText)
		}
		port = parsed
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, port, nil
}
