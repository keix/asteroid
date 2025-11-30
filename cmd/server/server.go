package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	signingService *signing.Service
	ctx            context.Context
	cancel         context.CancelFunc
}

// Assemble builds all dependencies and returns configured Asteroid
func Assemble() *Asteroid {
	gin.SetMode(gin.ReleaseMode)

	ctx, cancel := context.WithCancel(context.Background())

	cfg := config.Load()

	stores, err := driver.NewStores(&cfg)
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

	signingService := signing.NewFileService(
		ctx,
		"./keys",
		1*time.Minute,
		1*time.Minute,
	)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.SetTrustedProxies(nil)

	httpx.RegisterRoutes(r, cfg, stores, userinfoProvider, signingService)

	srv := &http.Server{
		Addr:    ":8880",
		Handler: r,
	}

	return &Asteroid{
		httpServer:     srv,
		signingService: signingService,
		ctx:            ctx,
		cancel:         cancel,
	}
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

	log.Println("Asteroid OIDC Provider running on :8880")
	if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("could not start server: %v", err)
	}

	<-a.ctx.Done()
}
