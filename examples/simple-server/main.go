// SPDX-License-Identifier: Apache-2.0
// Example: Simple Secured MCP Server
//
// This example demonstrates how to build a secured MCP server using the
// AegisGate MCP framework. It registers a tool, a resource, and a prompt,
// then serves over TCP with all 21 security layers active.
//
// Run:
//
//	go run ./examples/simple-server --addr :8081 --token my-secret
//
// Then connect with any MCP client (e.g. Claude Desktop, Cursor) pointing
// at the TCP address. For stdio or Streamable HTTP transport, see the
// library usage section in the README.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	mcp "github.com/aegisgatesecurity/aegisgate-mcp"
)

func main() {
	addr := flag.String("addr", ":8081", "Listen address")
	token := flag.String("token", "", "Bearer token for authentication")
	flag.Parse()

	// Configure the server
	cfg := mcp.DefaultServerConfig()
	cfg.Address = *addr
	cfg.AuthToken = *token
	cfg.DemoTools = false
	cfg.RateLimitRPM = 120
	cfg.ScanResponses = true

	server, err := mcp.NewSecuredMCPServer(cfg)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	// --- Register a Tool ---
	//
	// Tools are automatically scanned for prompt-injection poisoning
	// at registration time. If the description or inputSchema contains
	// malicious patterns, RegisterTool returns a *ToolPoisoningError
	// and the tool is NOT registered.
	err = server.RegisterTool("get_time", "Returns the current server time in RFC3339 format", 10, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"timezone": map[string]interface{}{
				"type":        "string",
				"description": "Optional timezone (e.g. America/New_York). Defaults to UTC.",
			},
		},
	})
	if err != nil {
		log.Fatalf("failed to register tool: %v", err)
	}

	server.RegisterToolHandler("get_time", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		tz, _ := params["timezone"].(string)
		if tz == "" {
			tz = "UTC"
		}
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("unknown timezone: %s", tz)
		}
		return time.Now().In(loc).Format(time.RFC3339), nil
	})

	// --- Register a Resource ---
	//
	// Resources are URI-addressable data sources that clients can read
	// via the resources/read JSON-RPC method.
	err = server.RegisterResource(
		"config://server/info",
		"Server Info",
		"Returns server configuration as JSON",
		"application/json",
		func(ctx context.Context, uri string) (*mcp.ResourceContent, error) {
			info := map[string]interface{}{
				"version":    mcp.Version,
				"protocol":   mcp.ProtocolVersion,
				"rate_limit": cfg.RateLimitRPM,
			}
			data, _ := json.Marshal(info)
			return &mcp.ResourceContent{
				URI:      uri,
				Text:     string(data),
				MimeType: "application/json",
			}, nil
		},
	)
	if err != nil {
		log.Fatalf("failed to register resource: %v", err)
	}

	// --- Register a Prompt ---
	//
	// Prompts are parameterized message templates that clients can invoke
	// via the prompts/get JSON-RPC method.
	err = server.RegisterPrompt(
		"code_review",
		"Generate a code review prompt for a given file",
		[]mcp.PromptArgument{
			{
				Name:        "filename",
				Description: "The name of the file to review",
				Required:    true,
			},
			{
				Name:        "language",
				Description: "Programming language (auto-detected if omitted)",
				Required:    false,
			},
		},
		func(ctx context.Context, args map[string]string) (*mcp.GetPromptResult, error) {
			filename := args["filename"]
			if filename == "" {
				return nil, fmt.Errorf("filename is required")
			}
			language := args["language"]
			if language == "" {
				language = "auto-detect"
			}
			return &mcp.GetPromptResult{
				Description: fmt.Sprintf("Code review for %s (%s)", filename, language),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: fmt.Sprintf(
							"Please review the file %s (language: %s) for security vulnerabilities, "+
								"code quality issues, and potential improvements. Focus on: "+
								"1) Input validation 2) Error handling 3) Resource leaks "+
								"4) Race conditions 5) Adherence to %s best practices.",
							filename, language, language,
						),
					},
				},
			}, nil
		},
	)
	if err != nil {
		log.Fatalf("failed to register prompt: %v", err)
	}

	// Load built-in policy rules (shell command blocking, file delete restrictions, etc.)
	server.LoadDefaultPolicies()

	// --- Start the Server ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	fmt.Printf("AegisGate MCP example server v%s (protocol %s)\n", mcp.Version, mcp.ProtocolVersion)
	fmt.Printf("Address: %s\n", *addr)
	fmt.Printf("Tools: 1 | Resources: 1 | Prompts: 1\n")
	if *token != "" {
		fmt.Println("Auth: enabled (bearer token)")
	} else {
		fmt.Println("Auth: disabled")
	}

	if err := server.Start(ctx); err != nil {
		log.Printf("server error: %v", err)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	server.Stop()
}
