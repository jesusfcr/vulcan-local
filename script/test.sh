#!/bin/bash

# Copyright 2021 Adevinta

# set -e   # Uncomment this to make the pipeline fail in case of a security vuln.

echo "Start target app"
docker pull appsecco/dsvw
docker run -p 1234:8000 --restart unless-stopped --name dsvw -d appsecco/dsvw

sleep 5

./vulcan-local -c ./vulcan.yaml -r report.json
echo "Test based on yaml config - exit=$?"

./vulcan-local -t . -e github -u file://./script/checktypes-stable.json
echo "Test local path as a git repository excluding the github check - exit=$?"

./vulcan-local -t http://localhost:1234 -e nessus -u file://./script/checktypes-stable.json
echo "Test local app as a webaddress excluding nessus - exit=$?"

docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock  \
    -v "$PWD":/target -e TRAVIS_BUILD_DIR=/target \
    vulcan-local -c /target/vulcan.yaml
echo "Docker test based on yaml config - exit=$?"

docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock -v \
    "$PWD":/target \
    vulcan-local -t /target -e github -u file:///target/script/checktypes-stable.json
echo "Docker test local path as a git repository excluding the github check - exit=$?"

docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock  \
    -v "$PWD":/target \
    vulcan-local -t http://localhost:1234 -e '(nessus|zap)' -u file:///target/script/checktypes-stable.json
echo "Docker test local app as a webaddress excluding nessus and zap - exit=$?"

echo "Stopping target app"
docker rm -f dsvw
