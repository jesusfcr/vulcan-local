/*
Copyright 2021 Adevinta
*/

package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue/sqs"
	"github.com/google/uuid"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/config"
	"github.mpi-internal.com/spt-security/vulcan-local/pkg/gitservice"
)

func getCheckType(cfg *config.Config, checkTypeRef config.ChecktypeRef) (*config.Checktype, error) {
	names := strings.Split(string(checkTypeRef), "/")
	repo := "default"
	name := names[0]
	if len(names) == 2 {
		repo = names[0]
		name = names[1]
	}
	if ct, ok := cfg.CheckTypes[config.ChecktypeRef(fmt.Sprintf("%s/%s", repo, name))]; ok {
		return &ct, nil
	} else {
		return nil, fmt.Errorf("unable to find checktype ref %s", checkTypeRef)
	}
}

// mergeOptions takes two check options.
func mergeOptions(optsA map[string]interface{}, optsB map[string]interface{}) map[string]interface{} {
	merged := map[string]interface{}{}
	for k, v := range optsA {
		merged[k] = v
	}
	for k, v := range optsB {
		merged[k] = v
	}
	return merged
}

func buildOptions(checktypeOpts, targetOpts map[string]interface{}) (string, error) {
	totalOptions := map[string]interface{}{}
	if len(checktypeOpts) > 0 {
		totalOptions = checktypeOpts
	}
	if len(targetOpts) > 0 {
		totalOptions = mergeOptions(totalOptions, targetOpts)
	}
	content, err := json.Marshal(totalOptions)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func GenerateJobs(cfg *config.Config, agentIp, hostIp string, gs gitservice.GitService, l log.Logger) ([]jobrunner.Job, error) {
	jobs := []jobrunner.Job{}
	for i := range cfg.Checks {

		// Because We want to update the original Check
		c := &cfg.Checks[i]

		ch, err := getCheckType(cfg, c.Type)
		if err != nil {
			l.Errorf("Skipping check - %s", err)
			continue
		}

		if !filterChecktype(ch.Name, cfg.Conf.Include, cfg.Conf.Exclude) {
			l.Debugf("Skipping filtered check=%s", ch.Name)
			continue
		}

		ops, err := buildOptions(ch.Options, c.Options)
		if err != nil {
			l.Errorf("Skipping check - %s", err)
			continue
		}
		c.Id = uuid.New().String()
		c.NewTarget = c.Target
		if stringInSlice("GitRepository", ch.Assets) {
			// TODO: Move util functions to pkg
			if path, err := GetValidGitDirectory(c.Target); err == nil {
				c.AssetType = "GitRepository"
				port, err := gs.AddGit(path)
				if err != nil {
					l.Errorf("Unable to create local git server check %w", err)
					continue
				}
				c.NewTarget = fmt.Sprintf("http://%s:%d/", agentIp, port)
			}
		}
		m1 := regexp.MustCompile(`(?i)(localhost|127.0.0.1)`)
		c.NewTarget = m1.ReplaceAllString(c.NewTarget, hostIp)

		// We allow all the checks to scan local assets.
		// This could be tunned depending on the target/assettype
		vars := append(ch.RequiredVars, "VULCAN_ALLOW_PRIVATE_IPS")

		l.Infof("Check name=%s image=%s target=%s new=%s type=%s id=%s", ch.Name, ch.Image, c.Target, c.NewTarget, c.AssetType, c.Id)
		jobs = append(jobs, jobrunner.Job{
			CheckID:      c.Id,
			StartTime:    time.Now(),
			Image:        ch.Image,
			Target:       c.NewTarget,
			Timeout:      ch.Timeout,
			Options:      ops,
			AssetType:    c.AssetType,
			RequiredVars: vars,
		})
	}
	return jobs, nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func AddAssetChecks(cfg *config.Config, a config.Asset, l log.Logger) error {
	checks := []config.Check{}
	for ref, ch := range cfg.CheckTypes {
		if stringInSlice(a.AssetType, ch.Assets) && filterChecktype(ch.Name, cfg.Conf.Include, cfg.Conf.Exclude) {
			checks = append(checks, config.Check{
				Type:      ref,
				Target:    a.Target,
				AssetType: a.AssetType,
				Options:   nil, // TODO: Allow options via flags (but options are related to a checktype)
			})
		}
	}
	cfg.Checks = append(cfg.Checks, checks...)
	return nil
}

func SendJobs(jobs []jobrunner.Job, arn, endpoint string, l log.Logger) error {
	qw, err := sqs.NewWriter(arn, endpoint, l)
	if err != nil {
		l.Errorf("error creating sqs writer %+v", err)
		return err
	}
	for _, job := range jobs {
		bytes, err := json.Marshal(job)
		if err != nil {
			return err
		}
		qw.Write(string(bytes))
	}
	return nil
}

func filterChecktype(name, include, exclude string) bool {
	// TODO: manage errors
	if include != "" {
		rei, _ := regexp.Match(include, []byte(name))
		return rei
	}
	if exclude != "" {
		rei, _ := regexp.Match(exclude, []byte(name))
		return !rei
	}
	return true
}

func validImageURI(imageURI string) error {
	// Based on https://github.com/distribution/distribution/blob/main/reference/reference.go#L1-L24
	// A tag is mandatory
	re := regexp.MustCompile(`(?i)(?P<name>[a-z0-9]+(?:[-_./][a-z0-9]+)*):(?P<tag>[\w][\w.-]{0,127})`)
	matches := re.FindStringSubmatch(imageURI)
	if matches == nil {
		return fmt.Errorf("not a valid image reference image='%s'", imageURI)
	}
	return nil
}

func PullImages(cfg *config.Config, jobs []jobrunner.Job, l log.Logger) error {
	commTemplate := ""
	strategy := strings.TrimSpace(strings.ToLower(cfg.Conf.PullPolicy))
	switch strategy {
	case "always":
		commTemplate = "docker pull IMG"
	case "ifnotpresent":
		commTemplate = "docker image inspect IMG || docker pull IMG"
	case "never":
		return nil
	default:
		return fmt.Errorf("invalid pullPolicy %s", cfg.Conf.PullPolicy)
	}
	pulled := map[string]interface{}{}
	for _, j := range jobs {
		if err := validImageURI(j.Image); err != nil {
			l.Errorf("Skipping wrong image %v", err)
		} else {
			if _, ok := pulled[j.Image]; !ok {
				command := strings.ReplaceAll(commTemplate, "IMG", j.Image)
				l.Debugf("Pulling image=%s strategy=%s", j.Image, strategy)
				cmd := exec.Command("sh", "-c", command)
				var cmdOut bytes.Buffer
				cmd.Stderr = &cmdOut
				err := cmd.Run()
				if err != nil {
					l.Errorf("unable to pull image %s %v %v", j.Image, err, cmdOut.String())
				}
				pulled[j.Image] = nil
			}
		}
	}
	return nil
}

func ImportRepositories(cfg *config.Config, l log.Logger) error {
	for key, uri := range cfg.Conf.Repositories {
		err := config.AddRepo(cfg, uri, key, l)
		if err != nil {
			l.Errorf("unable to add repository %s %+v", uri, err)
		}
	}
	if cfg.Conf.Repository != "" {
		err := config.AddRepo(cfg, cfg.Conf.Repository, "default", l)
		if err != nil {
			l.Errorf("unable to add repository %s %+v", cfg.Conf.Repository, err)
		}
	}
	return nil
}

func GetValidGitDirectory(path string) (string, error) {
	path, err := GetValidDirectory(path)
	if err != nil {
		return "", err
	}
	_, err = GetValidDirectory(filepath.Join(path, ".git"))
	if err != nil {
		return "", err
	}
	return path, nil
}

func GetValidDirectory(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path %v", err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("not a directory %s", path)
	}
	return path, nil
}
