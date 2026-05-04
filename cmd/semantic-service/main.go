package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mcpids/mcpids/internal/semantic"
)

func main() {
	if err := run(); err != nil {
		slog.Error("semantic-service: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	handler, err := semantic.NewClassifier(semantic.Options{
		Provider:       getenv("MCPIDS_SEMANTIC_BACKEND_PROVIDER", "stub"),
		Endpoint:       os.Getenv("MCPIDS_SEMANTIC_BACKEND_ENDPOINT"),
		BearerToken:    os.Getenv("MCPIDS_SEMANTIC_BACKEND_BEARER_TOKEN"),
		Model:          os.Getenv("MCPIDS_SEMANTIC_BACKEND_MODEL"),
		Timeout:        getenvDuration("MCPIDS_SEMANTIC_BACKEND_TIMEOUT", 2*time.Second),
		FallbackToStub: getenvBool("MCPIDS_SEMANTIC_BACKEND_FALLBACK_TO_STUB", true),
	})
	if err != nil {
		return fmt.Errorf("semantic-service: init backend: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "backend": handler.Name()})
	})
	mux.HandleFunc("/classify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var req semantic.ClassifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024*1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		result, err := handler.Classify(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	addr := getenv("MCPIDS_SEMANTIC_LISTEN_ADDR", ":8091")
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("semantic-service: listening", "addr", addr, "backend", handler.Name())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getenvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
