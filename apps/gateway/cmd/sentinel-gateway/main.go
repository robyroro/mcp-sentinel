package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const protocolVersion = "2025-11-25"

type config struct {
	APIURL          string
	APIToken        string
	Workspace       string
	ClientID        string
	ServerName      string
	UpstreamURL     string
	ListenAddress   string
	MaxPayloadBytes int64
	RequestTimeout  time.Duration
	ApprovalTimeout time.Duration
	AllowedOrigins  map[string]bool
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type evaluation struct {
	SessionID       string         `json:"session_id"`
	Decision        string         `json:"decision"`
	Explanation     string         `json:"explanation"`
	ApprovalID      *string        `json:"approval_id"`
	ForwardedParams map[string]any `json:"forwarded_params"`
}

type approvalStatus struct {
	Status            string         `json:"status"`
	ApprovedArguments map[string]any `json:"approved_arguments"`
}

type inspector struct {
	config config
	client *http.Client
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func loadConfig() config {
	origins := map[string]bool{}
	for _, value := range strings.Split(env("SENTINEL_ALLOWED_ORIGINS", "http://localhost:3000"), ",") {
		origins[strings.TrimSpace(value)] = true
	}
	return config{
		APIURL:          strings.TrimRight(env("SENTINEL_API_URL", "http://localhost:8000"), "/"),
		APIToken:        env("SENTINEL_GATEWAY_API_TOKEN", "dev-gateway-token-change-me"),
		Workspace:       env("SENTINEL_WORKSPACE", "acme-security"),
		ClientID:        env("SENTINEL_CLIENT_ID", "codex-local"),
		ServerName:      env("SENTINEL_SERVER_NAME", "Safe Filesystem"),
		UpstreamURL:     env("SENTINEL_UPSTREAM_URL", "http://safe-filesystem:9010/mcp"),
		ListenAddress:   env("SENTINEL_GATEWAY_LISTEN", ":8080"),
		MaxPayloadBytes: envInt64("SENTINEL_MAX_PAYLOAD_BYTES", 1_048_576),
		RequestTimeout:  60 * time.Second,
		ApprovalTimeout: 10 * time.Minute,
		AllowedOrigins:  origins,
	}
}

func validateMessage(data []byte, max int64) (rpcMessage, error) {
	if int64(len(data)) > max {
		return rpcMessage{}, fmt.Errorf("frame exceeds %d bytes", max)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var msg rpcMessage
	if err := decoder.Decode(&msg); err != nil {
		return rpcMessage{}, fmt.Errorf("invalid JSON-RPC frame: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return rpcMessage{}, errors.New("jsonrpc must equal 2.0")
	}
	if len(msg.ID) > 256 {
		return rpcMessage{}, errors.New("request id exceeds hard limit")
	}
	if msg.Method == "" && len(msg.Result) == 0 && len(msg.Error) == 0 {
		return rpcMessage{}, errors.New("frame is neither request, notification, nor response")
	}
	return msg, nil
}

func rawID(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return string(id)
	}
	return value
}

func paramsObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return map[string]any{}, nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("params must be a JSON object")
	}
	return value, nil
}

func (i *inspector) evaluate(ctx context.Context, message rpcMessage, sessionID string, serverName string) (evaluation, error) {
	params, err := paramsObject(message.Params)
	if err != nil {
		return evaluation{}, err
	}
	payload := map[string]any{
		"workspace_slug":    i.config.Workspace,
		"session_id":        nil,
		"client_identifier": i.config.ClientID,
		"server_name":       serverName,
		"method":            message.Method,
		"request_id":        rawID(message.ID),
		"params":            params,
		"protocol_version":  protocolVersion,
	}
	if sessionID != "" {
		payload["session_id"] = sessionID
	}
	var result evaluation
	if err := i.api(ctx, http.MethodPost, "/api/v1/internal/gateway/evaluate", payload, &result); err != nil {
		return evaluation{}, err
	}
	return result, nil
}

func (i *inspector) awaitApproval(ctx context.Context, approvalID string) (approvalStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, i.config.ApprovalTimeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		var result approvalStatus
		if err := i.api(ctx, http.MethodGet, "/api/v1/internal/gateway/approvals/"+url.PathEscape(approvalID), nil, &result); err != nil {
			return approvalStatus{}, err
		}
		switch result.Status {
		case "approved":
			return result, nil
		case "denied", "expired", "cancelled":
			return result, fmt.Errorf("approval finished with status %s", result.Status)
		}
		select {
		case <-ctx.Done():
			return approvalStatus{}, errors.New("approval wait timed out or was cancelled")
		case <-ticker.C:
		}
	}
}

func (i *inspector) recordResponse(ctx context.Context, sessionID string, message rpcMessage, payload map[string]any, duration time.Duration) (map[string]any, error) {
	request := map[string]any{
		"session_id":  sessionID,
		"request_id":  rawID(message.ID),
		"method":      message.Method,
		"payload":     payload,
		"duration_ms": float64(duration.Microseconds()) / 1000,
		"is_error":    len(message.Error) > 0,
	}
	var result struct {
		Payload map[string]any `json:"payload"`
	}
	err := i.api(ctx, http.MethodPost, "/api/v1/internal/gateway/response", request, &result)
	return result.Payload, err
}

func (i *inspector) api(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, i.config.APIURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+i.config.APIToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := i.client.Do(req)
	if err != nil {
		return fmt.Errorf("control plane unavailable (fail closed): %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, i.config.MaxPayloadBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > i.config.MaxPayloadBytes {
		return errors.New("control-plane response exceeds hard limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("control plane returned %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil && len(data) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("invalid control-plane response: %w", err)
		}
	}
	return nil
}

func errorResponse(id json.RawMessage, code int, message string, data any) []byte {
	response := map[string]any{"jsonrpc": "2.0", "id": rawID(id), "error": map[string]any{"code": code, "message": message, "data": data}}
	encoded, _ := json.Marshal(response)
	return encoded
}

func rewriteParams(original []byte, forwarded map[string]any) ([]byte, error) {
	var envelope map[string]any
	if err := json.Unmarshal(original, &envelope); err != nil {
		return nil, err
	}
	envelope["params"] = forwarded
	return json.Marshal(envelope)
}

type httpGateway struct {
	inspector *inspector
	upstream  *http.Client
}

func (g *httpGateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !g.inspector.config.AllowedOrigins[origin] {
		http.Error(w, "Origin is not allowed", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		g.proxyStream(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, g.inspector.config.MaxPayloadBytes+1))
	if err != nil || int64(len(body)) > g.inspector.config.MaxPayloadBytes {
		http.Error(w, "request exceeds payload limit", http.StatusRequestEntityTooLarge)
		return
	}
	message, err := validateMessage(body, g.inspector.config.MaxPayloadBytes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errorResponse(nil, -32700, "Invalid MCP message", err.Error()))
		return
	}
	serverName := strings.TrimPrefix(r.URL.Path, "/mcp/")
	if serverName == "" || serverName == r.URL.Path {
		serverName = g.inspector.config.ServerName
	} else if decoded, decodeErr := url.PathUnescape(serverName); decodeErr == nil {
		serverName = decoded
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.inspector.config.RequestTimeout+g.inspector.config.ApprovalTimeout)
	defer cancel()
	evaluated, err := g.inspector.evaluate(ctx, message, r.Header.Get("Mcp-Sentinel-Session-Id"), serverName)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(errorResponse(message.ID, -32001, "Sentinel policy service unavailable; request denied", nil))
		return
	}
	if evaluated.Decision == "require_approval" && evaluated.ApprovalID != nil {
		approved, approvalErr := g.inspector.awaitApproval(ctx, *evaluated.ApprovalID)
		if approvalErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(errorResponse(message.ID, -32003, "Approval denied, expired, or cancelled", map[string]any{"approval_id": *evaluated.ApprovalID}))
			return
		}
		if approved.ApprovedArguments != nil {
			if args, ok := evaluated.ForwardedParams["arguments"]; ok && args != nil {
				evaluated.ForwardedParams["arguments"] = approved.ApprovedArguments
			}
		}
	} else if evaluated.Decision == "deny" || evaluated.Decision == "terminate_session" || evaluated.Decision == "rate_limit" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(errorResponse(message.ID, -32002, "Request blocked by MCP Sentinel", evaluated.Explanation))
		return
	}
	forwarded, err := rewriteParams(body, evaluated.ForwardedParams)
	if err != nil {
		http.Error(w, "could not construct safe upstream request", http.StatusInternalServerError)
		return
	}
	g.proxyInspected(w, r, message, evaluated.SessionID, forwarded)
}

func (g *httpGateway) upstreamRequest(r *http.Request, body io.Reader) (*http.Request, error) {
	upstreamURL, err := url.Parse(g.inspector.config.UpstreamURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), body)
	if err != nil {
		return nil, err
	}
	for _, header := range []string{"Accept", "Content-Type", "Mcp-Protocol-Version", "Mcp-Session-Id", "Last-Event-ID"} {
		if value := r.Header.Get(header); value != "" {
			request.Header.Set(header, value)
		}
	}
	return request, nil
}

func (g *httpGateway) proxyInspected(w http.ResponseWriter, r *http.Request, message rpcMessage, sessionID string, body []byte) {
	started := time.Now()
	request, err := g.upstreamRequest(r, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "invalid upstream configuration", http.StatusBadGateway)
		return
	}
	response, err := g.upstream.Do(request)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(errorResponse(message.ID, -32004, "Upstream MCP server unavailable", nil))
		return
	}
	defer response.Body.Close()
	for _, header := range []string{"Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version"} {
		if value := response.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	w.Header().Set("Mcp-Sentinel-Session-Id", sessionID)
	contentType := response.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "text/event-stream") {
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(response.Body, g.inspector.config.MaxPayloadBytes))
		return
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, g.inspector.config.MaxPayloadBytes+1))
	if readErr != nil || int64(len(data)) > g.inspector.config.MaxPayloadBytes {
		http.Error(w, "upstream response exceeds hard limit", http.StatusBadGateway)
		return
	}
	var payload map[string]any
	if json.Unmarshal(data, &payload) == nil {
		redacted, inspectErr := g.inspector.recordResponse(r.Context(), sessionID, message, payload, time.Since(started))
		if inspectErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(errorResponse(message.ID, -32005, "Response inspection failed closed", nil))
			return
		}
		data, _ = json.Marshal(redacted)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(data)
}

func (g *httpGateway) proxyStream(w http.ResponseWriter, r *http.Request) {
	request, err := g.upstreamRequest(r, nil)
	if err != nil {
		http.Error(w, "invalid upstream configuration", http.StatusBadGateway)
		return
	}
	response, err := g.upstream.Do(request)
	if err != nil {
		http.Error(w, "upstream MCP server unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		if strings.EqualFold(key, "Content-Type") || strings.EqualFold(key, "Mcp-Session-Id") {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, g.inspector.config.MaxPayloadBytes*10))
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) line(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(append(data, '\n'))
	return err
}

func runStdio(ctx context.Context, insp *inspector, command []string) error {
	if len(command) == 0 {
		return errors.New("stdio mode requires -- followed by a server command")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) // #nosec G204 -- command is an explicit operator configuration.
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	clientOut := &lockedWriter{w: os.Stdout}
	serverWriter := &lockedWriter{w: serverIn}
	type pendingRequest struct {
		method    string
		sessionID string
		started   time.Time
	}
	pending := struct {
		sync.Mutex
		items map[string]pendingRequest
	}{items: map[string]pendingRequest{}}
	go func() {
		reader := bufio.NewReader(serverOut)
		for {
			line, readErr := reader.ReadBytes('\n')
			if readErr != nil {
				return
			}
			line = bytes.TrimSpace(line)
			message, validationErr := validateMessage(line, insp.config.MaxPayloadBytes)
			if validationErr != nil {
				continue
			}
			key := string(message.ID)
			pending.Lock()
			request := pending.items[key]
			delete(pending.items, key)
			pending.Unlock()
			var payload map[string]any
			if json.Unmarshal(line, &payload) == nil && request.sessionID != "" {
				inspected, inspectErr := insp.recordResponse(ctx, request.sessionID, rpcMessage{ID: message.ID, Method: request.method, Error: message.Error}, payload, time.Since(request.started))
				if inspectErr == nil {
					line, _ = json.Marshal(inspected)
				} else {
					line = errorResponse(message.ID, -32005, "Response inspection failed closed", nil)
				}
			}
			_ = clientOut.line(line)
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return readErr
		}
		line = bytes.TrimSpace(line)
		message, validationErr := validateMessage(line, insp.config.MaxPayloadBytes)
		if validationErr != nil {
			_ = clientOut.line(errorResponse(nil, -32700, "Invalid MCP message", validationErr.Error()))
			continue
		}
		lineCopy := append([]byte(nil), line...)
		go func() {
			evaluated, evaluateErr := insp.evaluate(ctx, message, "", insp.config.ServerName)
			if evaluateErr != nil {
				_ = clientOut.line(errorResponse(message.ID, -32001, "Sentinel unavailable; request denied", nil))
				return
			}
			if evaluated.Decision == "require_approval" && evaluated.ApprovalID != nil {
				approved, approvalErr := insp.awaitApproval(ctx, *evaluated.ApprovalID)
				if approvalErr != nil {
					_ = clientOut.line(errorResponse(message.ID, -32003, "Approval denied, expired, or cancelled", map[string]any{"approval_id": *evaluated.ApprovalID}))
					return
				}
				if approved.ApprovedArguments != nil {
					evaluated.ForwardedParams["arguments"] = approved.ApprovedArguments
				}
			} else if evaluated.Decision == "deny" || evaluated.Decision == "terminate_session" || evaluated.Decision == "rate_limit" {
				_ = clientOut.line(errorResponse(message.ID, -32002, "Request blocked by MCP Sentinel", evaluated.Explanation))
				return
			}
			forwarded, rewriteErr := rewriteParams(lineCopy, evaluated.ForwardedParams)
			if rewriteErr != nil {
				_ = clientOut.line(errorResponse(message.ID, -32602, "Invalid transformed parameters", nil))
				return
			}
			if len(message.ID) > 0 {
				pending.Lock()
				pending.items[string(message.ID)] = pendingRequest{method: message.Method, sessionID: evaluated.SessionID, started: time.Now()}
				pending.Unlock()
			}
			_ = serverWriter.line(forwarded)
		}()
	}
	_ = serverIn.Close()
	return cmd.Wait()
}

func main() {
	mode := "http"
	if len(os.Args) > 1 && (os.Args[1] == "http" || os.Args[1] == "stdio") {
		mode = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	flag.Parse()
	command := flag.Args()
	cfg := loadConfig()
	logger := log.New(os.Stderr, "", 0)
	insp := &inspector{config: cfg, client: &http.Client{Timeout: cfg.RequestTimeout}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if mode == "stdio" {
		if err := runStdio(ctx, insp, command); err != nil {
			logger.Printf("{\"level\":\"error\",\"message\":\"stdio gateway stopped\",\"error\":%q}", err.Error())
			os.Exit(1)
		}
		return
	}
	gateway := &httpGateway{inspector: insp, upstream: &http.Client{Timeout: cfg.RequestTimeout}}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"healthy","protocol_version":"`+protocolVersion+`"}`)
	})
	mux.HandleFunc("/mcp", gateway.serveMCP)
	mux.HandleFunc("/mcp/", gateway.serveMCP)
	server := &http.Server{Addr: cfg.ListenAddress, Handler: http.MaxBytesHandler(mux, cfg.MaxPayloadBytes), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: cfg.RequestTimeout, WriteTimeout: cfg.RequestTimeout + cfg.ApprovalTimeout, IdleTimeout: 90 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Printf("{\"level\":\"info\",\"message\":\"gateway listening\",\"address\":%q,\"mode\":\"streamable_http\",\"protocol_version\":%q}", cfg.ListenAddress, protocolVersion)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("{\"level\":\"error\",\"message\":\"gateway stopped\",\"error\":%q}", err.Error())
		os.Exit(1)
	}
}
