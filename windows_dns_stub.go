//go:build !windows

package main

// DetectWindowsDNS is a stub for non-Windows platforms
// Returns empty string to indicate no auto-detection available
func DetectWindowsDNS(logger *CondLogger) string {
	logger.Debug("Windows DNS auto-detection not available on this platform")
	return ""
}
