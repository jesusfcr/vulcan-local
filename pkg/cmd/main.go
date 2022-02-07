/*
Copyright 2021 Adevinta
*/

package cmd

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/phayes/freeport"
	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend/docker"
	agentconfig "github.com/adevinta/vulcan-agent/config"
	agentlog "github.com/adevinta/vulcan-agent/log"
	types "github.com/adevinta/vulcan-types"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/config"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/generator"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/gitservice"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/reporting"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/results"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/sqsservice"
)

const defaultDockerHost = "host.docker.internal"

func Run(cfg *config.Config, log *logrus.Logger) (int, error) {
	var err error

	log.SetLevel(agentlog.ParseLogLevel(cfg.Conf.LogLevel))

	if err = checkDependencies(cfg, log); err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unmet dependencies %+v", err)
	}

	if cfg.Conf.Include != "" {
		if cfg.Conf.IncludeR, err = regexp.Compile(cfg.Conf.Include); err != nil {
			return reporting.ErrorExitCode, fmt.Errorf("invalid include regexp %+v", err)
		}
	}
	if cfg.Conf.Exclude != "" {
		if cfg.Conf.ExcludeR, err = regexp.Compile(cfg.Conf.Exclude); err != nil {
			return reporting.ErrorExitCode, fmt.Errorf("invalid exclude regexp %+v", err)
		}
	}

	if _, err := reporting.FindSeverity(cfg.Reporting.Threshold); err != nil {
		return reporting.ErrorExitCode, err
	}

	err = generator.ImportRepositories(cfg, log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to generate checks %+v", err)
	}

	assets := []config.Asset{}
	if cfg.Asset.Target != "" {
		if cfg.Asset.AssetType == "" {
			if _, err2 := generator.GetValidGitDirectory(cfg.Asset.Target); err2 == nil {
				cfg.Asset.AssetType = "GitRepository"
				assets = append(assets, cfg.Asset)
				log.Debugf("Inferred asset type target=%s assetType=%s", cfg.Asset.Target, cfg.Asset.AssetType)
			} else {
				// Try to infer the asset type
				inferredAssets, err := getTypesFromIdentifier(cfg.Asset)
				if err != nil {
					return reporting.ErrorExitCode, fmt.Errorf("unable to infer assetType for target=%s %+v", cfg.Asset.Target, err)
				}
				assets = append(assets, inferredAssets...)
				for _, a := range inferredAssets {
					log.Debugf("Inferred asset type target=%s assetType=%s", a.Target, a.AssetType)
				}
			}
		} else {
			assets = append(assets, cfg.Asset)
		}

		// Add the checks for every target + assetType
		for _, a := range assets {
			generator.AddAssetChecks(cfg, a, log)
		}
	}

	agentIp := GetAgentIP(cfg.Conf.IfName, log)
	if agentIp == "" {
		return reporting.ErrorExitCode, fmt.Errorf("unable to get the agent ip %s", cfg.Conf.IfName)
	}

	hostIp := GetHostIP(log)
	if hostIp == "" {
		return reporting.ErrorExitCode, fmt.Errorf("unable to infer host ip")
	}

	gs := gitservice.New(log)
	defer gs.Shutdown()

	jobs, err := generator.GenerateJobs(cfg, agentIp, hostIp, gs, log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to generate checks %+v", err)
	}

	if len(jobs) == 0 {
		log.Infof("Empty list of checks")
		return reporting.SuccessExitCode, nil
	}

	err = generator.PullImages(cfg, jobs, log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to pull images %+v", err)
	}

	// AWS Credentials are required for sqs
	os.Setenv("AWS_REGION", "local")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "TBD")
	os.Setenv("AWS_ACCESS_KEY_ID", "TBD")

	sqs, err := sqsservice.Start(log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to parse start sqs server %+v", err)
	}
	defer sqs.Shutdown()

	results, err := results.Start(log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to start results server %+v", err)
	}
	defer results.Shutdown()

	err = generator.SendJobs(jobs, sqs.ArnChecks, sqs.Endpoint, log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to send jobs to queue %+v", err)
	}

	apiPort, err := freeport.GetFreePort()
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("unable to find a port for agent api %+v", err)
	}
	log.Debugf("Setting agent server on http://%s:%d/", agentIp, apiPort)

	vars := cfg.Conf.Vars
	// General config for the agent. Only the checks that require it will get this value.
	vars["VULCAN_ALLOW_PRIVATE_IPS"] = strconv.FormatBool(true)

	agentConfig := agentconfig.Config{
		Agent: agentconfig.AgentConfig{
			ConcurrentJobs:         cfg.Conf.Concurrency,
			MaxNoMsgsInterval:      5, // Low as all the messages will be in the queue before starting the agent.
			MaxProcessMessageTimes: 1, // No retry
			Timeout:                180,
		},
		SQSReader: agentconfig.SQSReader{
			Endpoint:          sqs.Endpoint,
			ARN:               sqs.ArnChecks,
			PollingInterval:   3,
			VisibilityTimeout: 120,
		},
		SQSWriter: agentconfig.SQSWriter{
			Endpoint: sqs.Endpoint,
			ARN:      sqs.ArnStatus,
		},
		Uploader: agentconfig.UploaderConfig{
			Endpoint: results.Endpoint,
		},
		API: agentconfig.APIConfig{
			Host: agentIp,
			Port: fmt.Sprintf(":%d", apiPort),
		},
		Check: agentconfig.CheckConfig{
			Vars: vars,
		},
	}

	backend, err := docker.NewBackend(log, agentConfig, nil)
	if err != nil {
		return reporting.ErrorExitCode, err
	}

	logAgent := log
	// Mute the agent to Error except if in Debug mode
	if log.Level != logrus.DebugLevel {
		logAgent = logrus.New()
		logAgent.SetFormatter(log.Formatter)
		logAgent.SetLevel(logrus.ErrorLevel)
	}
	exit := agent.Run(agentConfig, backend, logAgent.WithField("comp", "agent"))
	if exit != 0 {
		return reporting.ErrorExitCode, fmt.Errorf("error running the agent exit=%d", exit)
	}

	reportCode, err := reporting.Generate(cfg, results, log)
	if err != nil {
		return reporting.ErrorExitCode, fmt.Errorf("error generating report %+v", err)
	}

	return reportCode, nil
}

// checkDependencies checks that all the dependencies are present and run
// normally.
func checkDependencies(cfg *config.Config, log agentlog.Logger) error {
	var cmdOut bytes.Buffer

	log.Debugf("Checking dependency docker=%s", cfg.Conf.DockerBin)
	cmd := exec.Command(cfg.Conf.DockerBin, "ps", "-q")
	cmd.Stderr = &cmdOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("checking docker dependency bin=%s %w %s", cfg.Conf.DockerBin, err, cmdOut.String())
	}

	log.Debugf("Checking dependency git=%s", cfg.Conf.GitBin)
	cmd = exec.Command(cfg.Conf.GitBin, "version")
	cmd.Stderr = &cmdOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("checking git dependency bin=%s %w %s", cfg.Conf.GitBin, err, cmdOut.String())
	}
	return nil
}

func GetInterfaceAddr(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return "", err
		}

		// Check if it is IPv4.
		if ip.To4() != nil {
			return ip.To4().String(), nil
		}
	}

	return "", fmt.Errorf("failed to determine Docker agent IP address")
}

func GetAgentIP(ifacename string, log agentlog.Logger) string {
	ip, err := GetInterfaceAddr(ifacename)
	if err == nil {
		log.Debugf("Agent address iface=%s ip=%s", ifacename, ip)
		return ip
	}

	os := runtime.GOOS
	switch os {
	case "darwin":
		log.Debugf("Agent address os=%s ip=%s", os, defaultDockerHost)
		return defaultDockerHost
	case "linux":
		// Perhaps the agent is running in a container...
		ip, err = GetInterfaceAddr("eth0")
		if err == nil {
			log.Debugf("Agent address iface=eth0 os=%s ip=%s", os, ip)
			return ip
		}
	}
	log.Errorf("Unable to get agent address iface=%s os=%s", ifacename, os)
	return ""
}

func GetHostIP(l agentlog.Logger) string {
	cmd := exec.Command("docker", "run", "--rm", "busybox:1.34.1", "sh", "-c", "ip route|awk '/default/ { print $3 }'")
	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	err := cmd.Run()
	if err != nil {
		l.Errorf("unable to get Hostip %v %v", err, cmdOut.String())
		return ""
	}
	ip := strings.TrimSuffix(cmdOut.String(), "\n")
	l.Debugf("Hostip=%s", ip)
	return ip
}

// getTypesFromIdentifier infers the AssetType from an asset identifier
// This code is borrowed from https://github.com/adevinta/vulcan-api/blob/master/pkg/api/service/assets.go#L598
// could be moved to vulcan-types in order to allow reuse.
func getTypesFromIdentifier(asset config.Asset) ([]config.Asset, error) {
	identifier := asset.Target
	a := config.Asset{
		Target:  identifier,
		Options: asset.Options,
	}

	if types.IsAWSARN(identifier) {
		a.AssetType = "AWSAccount"
		return []config.Asset{a}, nil
	}

	if types.IsDockerImage(identifier) {
		a.AssetType = "DockerImage"
		return []config.Asset{a}, nil
	}

	if types.IsGitRepository(identifier) {
		a.AssetType = "GitRepository"
		return []config.Asset{a}, nil
	}

	if types.IsIP(identifier) {
		a.AssetType = "IP"
		return []config.Asset{a}, nil
	}

	if types.IsCIDR(identifier) {
		a.AssetType = "IPRange"

		// In case the CIDR has a /32 mask, remove the mask
		// and add the asset as an IP.
		if types.IsHost(identifier) {
			a.Target = strings.TrimSuffix(identifier, "/32")
			a.AssetType = "IP"
		}

		return []config.Asset{a}, nil
	}

	var assets []config.Asset

	isWeb := false
	if types.IsURL(identifier) {
		isWeb = true

		// From a URL like https://adevinta.com not only a WebAddress
		// type can be extracted, also a hostname (adevinta.com) and
		// potentially a domain name.
		u, err := url.ParseRequestURI(identifier)
		if err != nil {
			return nil, err
		}
		identifier = u.Hostname() // Overwrite identifier to check for hostname and domain.
	}

	if types.IsHostname(identifier) {
		h := config.Asset{
			Target:    identifier,
			AssetType: "Hostname",
		}
		assets = append(assets, h)

		// Add WebAddress type only for URLs with valid hostnames.
		if isWeb {
			// At this point a.Target contains the original identifier,
			// not the overwritten identifier.
			a.AssetType = "WebAddress"
			assets = append(assets, a)
		}
	}

	ok, err := types.IsDomainName(identifier)
	if err != nil {
		return nil, fmt.Errorf("can not guess if the asset is a domain: %v", err)
	}
	if ok {
		d := config.Asset{
			Target:    identifier,
			AssetType: "DomainName",
		}
		assets = append(assets, d)
	}

	return assets, nil
}
