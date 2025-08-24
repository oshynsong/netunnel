package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oshynsong/netunnel/app/assets"
	"github.com/oshynsong/netunnel/app/tray"
	"github.com/oshynsong/netunnel/app/tray/menu"
)

const (
	iconName    = "app.ico"
	serviceName = "netunnel"
)

func AppRun() {
	iconBytes, err := assets.GetIcon(iconName)
	if err != nil {
		slog.Error(fmt.Sprintf("get app icon failed: %v", err))
		return
	}

	var s tray.Service
	s, err = tray.New(serviceName, iconBytes)
	if err != nil {
		slog.Error(fmt.Sprintf("create tray service error: %v", err))
		return
	}

	if err := setupLayout(s); err != nil {
		slog.Error(fmt.Sprintf("setup layout error: %v", err))
		return
	}
	s.Run()
}

func setupLayout(s tray.Service) error {
	startServerMenu := menu.Add("Start Server", "start netunnel as a server", nil)
	stopServerMenu := menu.Add("Stop Server", "stop netunnel server", nil)
	if err := s.UpsertMenuItem(startServerMenu, stopServerMenu); err != nil {
		return err
	}

	if err := s.AddSeperator(); err != nil {
		return err
	}
	quitMetu := menu.Add("Quit", "quit netunnel", nil)
	if err := s.UpsertMenuItem(quitMetu); err != nil {
		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-startServerMenu.Event():
				slog.Info("start server event got")
			case <-stopServerMenu.Event():
				slog.Info("stop server event got")
			case <-signals:
				slog.Info("exit signal got")
				s.Quit()
			case <-quitMetu.Event():
				slog.Info("quit event got")
				s.Quit()
			}
		}
	}()
	return nil
}
