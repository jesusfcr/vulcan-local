/*
Copyright 2021 Adevinta
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/cmd"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/config"
)

const envDefaultChecktypesUri = "VULCAN_CHECKTYPES_URI"

func main() {
	exitCode := 1
	defer os.Exit(exitCode)

	var err error

	var log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		ForceColors:     true,
	})

	cfg := &config.DefaultConfig
	var help bool
	var configFile string
	flag.BoolVar(&help, "h", false, "print usage")
	flag.StringVar(&configFile, "c", "", "config file (i.e. -c vulcan.yaml)")
	flag.StringVar(&cfg.Conf.LogLevel, "l", cfg.Conf.LogLevel, "log level (panic, fatal, error, warn, info, debug)")
	flag.StringVar(&cfg.Reporting.OutputFile, "r", "", "results file (i.e. -r results.json)")
	flag.StringVar(&cfg.Conf.Include, "i", cfg.Conf.Include, "include checktype regex")
	flag.StringVar(&cfg.Conf.Exclude, "e", cfg.Conf.Exclude, "exclude checktype regex")
	flag.StringVar(&cfg.Asset.Target, "t", "", "target to check")
	flag.StringVar(&cfg.Asset.AssetType, "a", "", "asset type (WebAddress, ...)")
	flag.StringVar(&cfg.Reporting.Threshold, "s", cfg.Reporting.Threshold, "severity threshold (NONE, LOW, MEDIUM, HIGH, CRITICAL)")
	flag.StringVar(&cfg.Conf.Repository, "u", "", fmt.Sprintf("chektypes uri (or %s)", envDefaultChecktypesUri))
	flag.StringVar(&cfg.Conf.DockerBin, "docker", cfg.Conf.DockerBin, "docker binary")
	flag.StringVar(&cfg.Conf.GitBin, "git", cfg.Conf.GitBin, "git binary")
	flag.StringVar(&cfg.Conf.IfName, "ifname", cfg.Conf.IfName, "network interface where agent will be available for the checks")
	flag.IntVar(&cfg.Conf.Concurrency, "concurrency", cfg.Conf.Concurrency, "max number of checks/containers to run concurrently")
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	if cfg.Conf.Repository == "" {
		if repo := os.Getenv(envDefaultChecktypesUri); repo != "" {
			cfg.Conf.Repository = repo
		}
	}

	if configFile != "" {
		err = config.ReadConfig(configFile, cfg, log)
		if err != nil {
			log.Errorf("Unable to parse config file %s %+v", configFile, err)
			return
		}
		// Overwrite the yaml config with the command line flags.
		flag.Parse()
	}
	exitCode, err = cmd.Run(cfg, log)
	if err != nil {
		log.Print(err)
	}
	os.Exit(exitCode)
}
