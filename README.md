# vulcan-local

## ⚠️ Alpha status

This tool is under active development and for sure will break compatibility until it gets a stable release.

## Installing

```sh
go install github.mpi-internal.com/spt-security/vulcan-local@latest
```

## vulcan.yaml config file

This tool accepts a configuration file.

An example file is provided in [vulcan.yaml](./vulcan.yaml).

The main sections are:

- variables: Some config vars sent to the checks, i.e. to allow access to private resources.
- repositories: http or file uris pointing to checktype definitions.
- checks: The list of specific checks to run.

This is a very simple config file with two checks:

```yaml
conf:
  repositories:
    # A local checktype uri
    default: file://./script/checktypes-stable.json

checks:
  # Check current path
  - type: vulcan-seekret
    target: .

  # Check with default options
  - type: vulcan-zap
    target: http://localhost:1234
```

## Executing

Requirements:

- Docker has to be running on the local machine.
- Git

Usage:

```sh
Usage of out/vulcan-local:
  -a string
    	asset type (WebAddress, ...)
  -c string
    	config file (i.e. -c vulcan.yaml)
  -concurrency int
    	max number of checks/containers to run concurrently (default 5)
  -docker string
    	docker binary (default "docker")
  -e string
    	exclude checktype regex
  -git string
    	git binary (default "git")
  -h	print usage
  -i string
    	include checktype regex
  -ifname string
    	network interface where agent will be available for the checks (default "docker0")
  -l string
    	log level (panic, fatal, error, warn, info, debug) (default "info")
  -r string
    	results file (i.e. -r results.json)
  -s string
    	severity threshold (NONE, LOW, MEDIUM, HIGH, CRITICAL) (default "HIGH")
  -t string
    	target to check
  -u string
    	chektypes uri (or VULCAN_CHECKTYPES_URI)
```

Exit codes:

- 0: No vulnerability found over the severity threshold (see -s flag)
- 1: An error happened
- 101: Max severity found was LOW
- 102: Max severity found was MEDIUM
- 103: Max severity found was HIGH
- 104: Max severity found was CRITICAL

Scanning the checks defined in vulcan.yaml

```sh
vulcan-local -c vulcan.yaml
```

NOTE: This application does not handle authentication in private registries
instead it assumes the current docker client is already authenticated in the required registries.
If the check images are from private registries first login into the registry.

```sh
cat ~/my_password.txt | docker login --username foo --password-stdin private.registry.com
```

Scan a single asset with all the checkTypes that apply

```sh
vulcan-local -t http://localhost:1234 -i exposed -u file://./script/checktypes-stable.json

# Set VULCAN_CHECKTYPES_URI as the default checktypes uri (-u flag)
export VULCAN_CHECKTYPES_URI=file://./script/checktypes-stable.json

# Execute all checks on WebAddress that matches 'exposed' regex
vulcan-local -t http://localhost:1234 -i exposed

# Execute all checks on WebAddress that doesn't matches 'zap' regex
vulcan-local -t http://localhost:1234 -e zap

# Execute all checks for GitRepository targets (. has to be the root of a git repo)
vulcan-local -t . -a GitRepository

# Execute all checks . inferring the asset type
vulcan-local -t .
```

## Docker usage

Using the existing docker image:

```sh
docker pull containers.mpi-internal.com/spt-security/vulcan-local:latest
```

Building your local docker image:

```sh
docker build . -t vulcan-local
```

In the following examples the local image reference `vulcan-local` will e used.

Start the target application

```sh
docker run -p 1234:8000 --restart unless-stopped -d appsecco/dsvw 
```

Start scan using a local config file

```sh
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD/script:/app/script \
    vulcan-local -c /app/vulcan.yaml
```

Start scanning a local http server

```sh
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD/script:/app/script \
    vulcan-local -t http://localhost:1234 -u file:///app/script/checktypes-stable.json
```

Start scanning a local Git repository. **The target path must point to the base of a git repository.**

```sh
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $PWD/script:/app/script -v $PWD:/src \
  vulcan-local -t /src -u file:///app/script/checktypes-stable.json
```
