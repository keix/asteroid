package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/config"
	httpx "asteroid/internal/http"
	"asteroid/internal/loader/data"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store/driver"
	"asteroid/internal/userinfo/source"

	"github.com/gin-gonic/gin"
)

// Asteroid represents the complete OIDC provider
type Asteroid struct {
	httpServer     *http.Server
	listener       net.Listener
	listenAddr     string
	signingService *signing.Service
	ctx            context.Context
	cancel         context.CancelFunc
}

// Assemble builds all dependencies and returns configured Asteroid
func Assemble() *Asteroid {
	gin.SetMode(gin.ReleaseMode)

	ctx, cancel := context.WithCancel(context.Background())

	cfg := config.Load()

	clk := clock.RealClock{}

	stores, err := driver.NewStores(&cfg, clk)
	if err != nil {
		log.Fatalf("failed to initialize stores: %v", err)
	}

	// Load client seed data (clients still need eager loading)
	loader := data.NewLoader("./data")
	if err := loader.LoadAll(context.Background(), stores); err != nil {
		log.Fatalf("failed to load seed data: %v", err)
	}

	// Initialize userinfo provider (lazy loading from YAML)
	userinfoProvider := source.NewYAMLProvider("./data/users.yaml")

	// When run under systemd with StateDirectory=, use the writable state dir;
	// otherwise fall back to ./keys for local development.
	keyDir := "./keys"
	if sd := os.Getenv("STATE_DIRECTORY"); sd != "" {
		keyDir = filepath.Join(sd, "keys")
	}

	signingService := signing.NewFileService(
		ctx,
		keyDir,
		24*time.Hour, // Key Retention: 1 days
		24*time.Hour, // Key Rotation: 1 day
		clk,
	)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.SetTrustedProxies(nil)

	httpx.RegisterRoutes(r, cfg, stores, userinfoProvider, signingService)

	srv := &http.Server{
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	listener, addr, err := makeListener()
	if err != nil {
		log.Fatalf("failed to bind listener: %v", err)
	}

	return &Asteroid{
		httpServer:     srv,
		listener:       listener,
		listenAddr:     addr,
		signingService: signingService,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// makeListener binds either a unix socket (when systemd provides RUNTIME_DIRECTORY)
// or TCP :8880 for local development. The unix socket is chmod'd to 0660 so
// members of the service group (e.g. nginx) can connect while others cannot.
func makeListener() (net.Listener, string, error) {
	if rd := os.Getenv("RUNTIME_DIRECTORY"); rd != "" {
		path := filepath.Join(rd, "asteroid.sock")
		// Remove any stale socket from an unclean previous run.
		_ = os.Remove(path)

		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, "", err
		}
		if err := os.Chmod(path, 0660); err != nil {
			l.Close()
			return nil, "", err
		}
		return l, fmt.Sprintf("unix socket: %s", path), nil
	}

	l, err := net.Listen("tcp", ":8880")
	if err != nil {
		return nil, "", err
	}
	return l, ":8880", nil
}

// Run starts the server with graceful shutdown
func (a *Asteroid) Run() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down Asteroid OIDC Provider...")

		a.signingService.Close()
		a.cancel()

		ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelTimeout()

		if err := a.httpServer.Shutdown(ctxTimeout); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}

		log.Println("Asteroid shutdown complete.")
	}()

	log.Printf("Asteroid OIDC Provider running on %s", a.listenAddr)
	if err := a.httpServer.Serve(a.listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("could not start server: %v", err)
	}
}
