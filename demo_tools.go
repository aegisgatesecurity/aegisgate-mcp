// SPDX-License-Identifier: Apache-2.0
// Demo Tools — three example tools for testing and demonstration.
// Enabled via the --demo flag or by calling RegisterDemoTools directly.

package mcpsecurity

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// RegisterDemoTools registers three example tools on the server:
//   - ping: returns "pong" (risk level 10, read-only)
//   - system_info: returns server runtime info (risk level 30, read-only)
//   - echo: echoes back the provided message (risk level 20)
//
// These tools are safe, read-only, and do not access the filesystem,
// network, or any external resources. They exist so the server has
// something to return for tools/list out of the box.
func RegisterDemoTools(server *SecuredMCPServer) error {
	// --- ping ---
	if err := server.RegisterTool("ping", "Returns 'pong' — health check tool", 10, map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []interface{}{},
	}); err != nil {
		return err
	}
	if err := server.RegisterToolHandler("ping", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "pong", nil
	}); err != nil {
		return err
	}

	// --- system_info ---
	if err := server.RegisterTool("system_info", "Returns server runtime information (Go version, OS, arch, uptime)", 30, map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []interface{}{},
	}); err != nil {
		return err
	}
	if err := server.RegisterToolHandler("system_info", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"go_version": runtime.Version(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
			"cpus":       runtime.NumCPU(),
			"goroutines": runtime.NumGoroutine(),
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		}, nil
	}); err != nil {
		return err
	}

	// --- echo ---
	if err := server.RegisterTool("echo", "Echoes back the provided message", 20, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"message": map[string]interface{}{
				"type":        "string",
				"description": "The message to echo back",
			},
		},
		"required": []interface{}{"message"},
	}); err != nil {
		return err
	}
	if err := server.RegisterToolHandler("echo", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		msg, ok := params["message"].(string)
		if !ok {
			return nil, fmt.Errorf("parameter 'message' must be a string")
		}
		return msg, nil
	}); err != nil {
		return err
	}

	return nil
}
