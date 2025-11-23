//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// DetectWindowsDNS attempts to auto-detect Windows DNS configuration
// Returns DoH URL if configured, empty string otherwise
func DetectWindowsDNS(logger *CondLogger) string {
	// Try to detect DoH configuration from Windows registry
	// Windows 10/11 DoH settings are stored in:
	// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohPolicy

	dohURL := detectDoHFromRegistry(logger)
	if dohURL != "" {
		logger.Info("Auto-detected Windows DoH: %s", dohURL)
		return dohURL
	}

	// Try to detect DNS servers from network interfaces
	dnsServers := detectDNSServers(logger)
	if len(dnsServers) > 0 {
		logger.Info("Auto-detected DNS servers: %v (will use TCP DNS through tunnel)", dnsServers)
		// Return empty string to indicate TCP DNS should be used
		return ""
	}

	logger.Info("No Windows DNS configuration detected, will use default TCP DNS through tunnel")
	return ""
}

// detectDoHFromRegistry checks Windows registry for DoH configuration
func detectDoHFromRegistry(logger *CondLogger) string {
	// Check DohPolicy settings
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		logger.Debug("Cannot open Dnscache registry key: %v", err)
		return ""
	}
	defer key.Close()

	// Check for DoH policy
	dohPolicy, _, err := key.GetIntegerValue("EnableAutoDoh")
	if err == nil && dohPolicy > 0 {
		logger.Debug("DoH is enabled via EnableAutoDoh")
	}

	// Try to read DoH template
	// Windows may store DoH templates in various locations
	// Check for configured DoH servers in DohSettings
	dohKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohSettings`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		logger.Debug("Cannot open DohSettings registry key: %v", err)
		return ""
	}
	defer dohKey.Close()

	// Enumerate DoH server configurations
	subkeys, err := dohKey.ReadSubKeyNames(-1)
	if err != nil {
		logger.Debug("Cannot read DohSettings subkeys: %v", err)
		return ""
	}

	for _, subkey := range subkeys {
		serverKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohSettings\%s`, subkey),
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Try to read the template
		template, _, err := serverKey.GetStringValue("DohTemplate")
		serverKey.Close()

		if err == nil && template != "" {
			logger.Debug("Found DoH template: %s", template)
			return template
		}
	}

	return ""
}

// detectDNSServers detects configured DNS servers from network interfaces
func detectDNSServers(logger *CondLogger) []string {
	var dnsServers []string

	// Check TCP/IP parameters for each interface
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		logger.Debug("Cannot open Tcpip Interfaces registry key: %v", err)
		return dnsServers
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		logger.Debug("Cannot read interface subkeys: %v", err)
		return dnsServers
	}

	for _, subkey := range subkeys {
		ifaceKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s`, subkey),
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Try NameServer first (comma or space separated)
		nameServer, _, err := ifaceKey.GetStringValue("NameServer")
		if err == nil && nameServer != "" {
			servers := strings.FieldsFunc(nameServer, func(r rune) bool {
				return r == ',' || r == ' '
			})
			dnsServers = append(dnsServers, servers...)
		}

		// Try DhcpNameServer if NameServer not found
		if len(dnsServers) == 0 {
			dhcpNameServer, _, err := ifaceKey.GetStringValue("DhcpNameServer")
			if err == nil && dhcpNameServer != "" {
				servers := strings.FieldsFunc(dhcpNameServer, func(r rune) bool {
					return r == ',' || r == ' '
				})
				dnsServers = append(dnsServers, servers...)
			}
		}

		ifaceKey.Close()

		if len(dnsServers) > 0 {
			break // Found servers, no need to check more interfaces
		}
	}

	return dnsServers
}
