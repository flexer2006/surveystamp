package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flexer2006/surveystamp/internal/adapters/api"
	"github.com/flexer2006/surveystamp/internal/adapters/crypt"
	"github.com/flexer2006/surveystamp/internal/adapters/mem"
	"github.com/flexer2006/surveystamp/internal/app"
	"github.com/flexer2006/surveystamp/internal/domain"
)

const (
	shutdownTimeout = 5 * time.Second
	port            = "9696"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, err := crypt.Generate(nil)
	if err != nil {
		return err
	}

	srv := new(http.Server{
		Addr:    ":"+port,
		Handler: api.New(app.NewService(clock{}, ids{}, signer, mem.New())),
	})

	go func() {
		<-ctx.Done()

		sh, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		_ = srv.Shutdown(sh)
	}()

	slog.Info("listen", "addr", srv.Addr)

	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

type clock struct{}

func (clock) Now() time.Time { return time.Now().UTC() }

type ids struct{}

func (ids) NewID() (domain.AttestationID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	return domain.NewAttestationID(hex.EncodeToString(b[:])), nil
}
