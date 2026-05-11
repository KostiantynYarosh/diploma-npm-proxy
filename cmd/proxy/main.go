package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/npm-proxy/internal/analyzer"
	"github.com/yourusername/npm-proxy/internal/analyzer/layer1"
	"github.com/yourusername/npm-proxy/internal/cache"
	"github.com/yourusername/npm-proxy/internal/config"
	"github.com/yourusername/npm-proxy/internal/policy"
	"github.com/yourusername/npm-proxy/internal/proxy"
	"github.com/yourusername/npm-proxy/internal/recheck"
	"github.com/yourusername/npm-proxy/internal/registry"
	"github.com/yourusername/npm-proxy/internal/siem"
)

func main() {
	cfgPath := flag.String("config", "configs/proxy.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// SIEM emitter
	siemEmitter := siem.New(
		cfg.SIEM.Mode,
		cfg.SIEM.SyslogAddr,
		cfg.SIEM.SyslogNetwork,
		cfg.SIEM.WebhookURL,
		cfg.SIEM.WebhookSecret,
		cfg.SIEM.BufferSize,
	)
	defer siemEmitter.Close()

	// Registry client
	regClient := registry.New(
		cfg.Proxy.UpstreamURL,
		time.Duration(cfg.Registry.ConnectTimeoutSec)*time.Second,
		time.Duration(cfg.Registry.TotalTimeoutSec)*time.Second,
		cfg.Registry.MaxRetries,
	)

	// Redis cache
	cacheClient := cache.New(
		cfg.Cache.RedisAddr,
		cfg.Cache.RedisPassword,
		cfg.Cache.RedisDB,
		cfg.Cache.VerdictTTLHours,
		cfg.Cache.OSVTTLHours,
	)
	ctx := context.Background()
	if err := cacheClient.Ping(ctx); err != nil {
		// Cache miss is the failure mode - every request will run the full
		// pipeline until Redis is reachable again. We do NOT exit, because the
		// proxy must remain available even with a degraded cache; instead we
		// surface a loud warning so monitoring can pick it up.
		log.Printf("WARNING: redis unavailable at %s (%v) - verdict & OSV caching DISABLED, every request will pay full analysis cost", cfg.Cache.RedisAddr, err)
	}

	// Layer 1 checkers
	osvChecker := layer1.NewOSVChecker(
		cacheClient,
		cfg.Layer1.OSVAPIUrl,
		time.Duration(cfg.Layer1.OSVTimeoutSec)*time.Second,
	)

	typoChecker, err := layer1.NewTyposquatChecker(
		cfg.Layer1.Top10kPath,
		layer1.TyposquatOptions{
			CloseDistance:       cfg.Layer1.TyposquatCloseDistance,
			CloseScore:          cfg.Layer1.TyposquatCloseScore,
			WarnDistance:        cfg.Layer1.TyposquatWarnDistance,
			WarnScore:           cfg.Layer1.TyposquatWarnScore,
			ASCIIHomoglyphScore: cfg.Layer1.TyposquatASCIIHomoglyphScore,
			CombosquatScore:     cfg.Layer1.TyposquatCombosquatScore,
			ScopeCloseScore:     cfg.Layer1.TyposquatScopeCloseScore,
			ScopeWarnScore:      cfg.Layer1.TyposquatScopeWarnScore,
		},
	)
	if err != nil {
		log.Fatalf("load top10k list: %v", err)
	}

	metaChecker := layer1.NewMetadataChecker(regClient, layer1.MetadataCheckerOptions{
		NewPackageDays:        cfg.Layer1.MetadataNewPackageDays,
		NewPackageScore:       cfg.Layer1.MetadataNewPackageScore,
		YoungMaintainerDays:   cfg.Layer1.MetadataYoungMaintainerDays,
		YoungMaintainerScore:  cfg.Layer1.MetadataYoungMaintainerScore,
		LowDownloadsThreshold: cfg.Layer1.MetadataLowDownloadsThreshold,
		LowDownloadsScore:     cfg.Layer1.MetadataLowDownloadsScore,
		PopularThreshold:      cfg.Layer1.MetadataPopularThreshold,
		PopularButStaleDays:   cfg.Layer1.MetadataPopularStaleDays,
		PopularButStaleScore:  cfg.Layer1.MetadataPopularStaleScore,
		NetTimeout:            time.Duration(cfg.Layer1.MetadataNetTimeoutSec) * time.Second,
	})

	anomalyChecker := layer1.NewAnomalyChecker(layer1.AnomalyCheckerOptions{
		MaxVersionsPerDay:     cfg.Layer1.AnomalyMaxVersionsPerDay,
		VersionSpikeScore:     cfg.Layer1.AnomalyVersionSpikeScore,
		MaintainerChangeScore: cfg.Layer1.AnomalyMaintainerChangeScore,
		UnusualHoursScore:     cfg.Layer1.AnomalyUnusualHoursScore,
		SizeDeviationScore:    cfg.Layer1.AnomalySizeDeviationScore,
	})

	licenseChecker := layer1.NewLicenseChecker(
		cfg.Layer1.LicensePatchChangeScore,
		cfg.Layer1.LicenseMissingPopScore,
		cfg.Layer1.LicensePopularDownloads,
	)

	// Post-download analysis engine
	engine := analyzer.NewPostDownloadEngine(cfg, regClient)

	// Policy engine
	policyEngine := policy.NewEngine(cfg.Policy.AllowThreshold, cfg.Policy.BlockThreshold, cfg.Policy.MinCategories)

	// HTTP handler
	handler := proxy.NewHandler(
		cfg,
		regClient,
		cacheClient,
		siemEmitter,
		engine,
		policyEngine,
		osvChecker,
		typoChecker,
		metaChecker,
		anomalyChecker,
		licenseChecker,
	)

	srv := &http.Server{
		Addr:         cfg.Proxy.ListenAddr,
		Handler:      handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Background post-factum rechecker.
	var recheckCancel context.CancelFunc
	if cfg.Recheck.Enabled {
		rcCtx, cancel := context.WithCancel(context.Background())
		recheckCancel = cancel
		rc := recheck.New(
			recheck.Config{
				Interval:  time.Duration(cfg.Recheck.IntervalHours) * time.Hour,
				BatchSize: cfg.Recheck.BatchSize,
				WarnOnly:  cfg.Recheck.WarnOnly,
			},
			cacheClient,
			osvChecker,
			typoChecker,
			policyEngine,
			siemEmitter,
		)
		go rc.Run(rcCtx)
	}

	go func() {
		log.Printf("npm-proxy listening on %s → %s", cfg.Proxy.ListenAddr, cfg.Proxy.UpstreamURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down…")
	if recheckCancel != nil {
		recheckCancel()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = cacheClient.Close()
}
