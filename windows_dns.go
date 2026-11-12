//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// DetectWindowsDNS attempts to auto-detect Windows DNS configuration
// Returns DoH URL if configured, empty string otherwise.
// Plain DNS servers of the local interfaces are deliberately not used: they
// are usually LAN/ISP addresses that are unreachable (or point elsewhere)
// when queried from the Windscribe server through the tunnel.
func DetectWindowsDNS(logger *CondLogger) string {
	// Try to detect DoH configuration from Windows registry
	// Windows 10/11 DoH settings are stored in:
	// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohPolicy

	dohURL := detectDoHFromRegistry(logger)
	if dohURL != "" {
		logger.Info("Auto-detected Windows DoH: %s", dohURL)
		return dohURL
	}

	logger.Info("No Windows DoH configuration detected, will use default TCP DNS through tunnel")
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
