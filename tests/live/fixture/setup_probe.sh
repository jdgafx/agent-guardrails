#!/bin/bash
# Builds the throwaway probe tree of tests/live/t014_probe.py (fake secrets only). Usage: setup_probe.sh <new empty folder>
# Every secret is fake text FAKE-<NAME>-MARKER-<nn>. "Listed" = a denyRead entry of the generated block masks it.
set -e
P=${1:?usage: setup_probe.sh <folder>}; rm -rf "$P"; mkdir -p "$P/out"; H=$P/home; R=$H/proj
mkdir -p $H/.ssh $H/.aws $H/.config/gh $H/.kube $H/.config/gcloud $H/.docker $H/other $R/sub/a/b/c/d/e/f/g $P/outside
echo "FAKE-SSH-KEY-MARKER-01" > $H/.ssh/id_ed25519                                   # listed (~/.ssh)
echo "ssh-ed25519 PUBLIC-OK" > $H/.ssh/id_ed25519.pub                                # masked with the folder
printf '[default]\naws_secret_access_key = FAKE-AWS-MARKER-02\n' > $H/.aws/credentials # listed
echo "oauth_token: FAKE-GH-MARKER-03" > $H/.config/gh/hosts.yml                      # listed (~/.config/gh/hosts.yml)
echo "token: FAKE-KUBE-MARKER-04" > $H/.kube/config                                  # listed
echo "machine x login u password FAKE-NETRC-MARKER-05" > $H/.netrc                   # listed
echo '{"k":"FAKE-GCLOUD-MARKER-06"}' > $H/.config/gcloud/application_default_credentials.json  # listed
echo "https://u:FAKE-GITCRED-MARKER-15@github.com" > $H/.git-credentials             # listed
echo '{"auths":"FAKE-DOCKER-MARKER-16"}' > $H/.docker/config.json                     # listed
printf '[credential]\n\thelper = store\n' > $H/.gitconfig
echo "OTHER=FAKE-OTHER-ENV-MARKER-13" > $H/other/.env                                # NOT listed (limit: under ~, outside project)
echo "OUT=FAKE-OUTSIDE-ENV-MARKER-12" > $P/outside/.env                              # NOT listed (limit: outside ~)
cd $R
printf '.env*\n!.env.example\n' > .gitignore
echo "API=FAKE-ENV-MARKER-07" > .env                                                 # listed
echo "P=FAKE-ENVPROD-MARKER-08" > .env.production                                    # listed
echo "EX=EXAMPLE-OK" > .env.example                                                  # re-opened by allowRead
echo "//registry/:_authToken=FAKE-NPMRC-MARKER-09" > .npmrc                          # listed
echo "D=FAKE-DEEP-ENV-MARKER-10" > sub/a/b/c/d/e/f/g/.env                            # listed, gitignored, 8 folders down
echo "FAKE-PEM-MARKER-11" > server.pem                                               # NOT listed (deny-key-files not isolated)
echo "# readme" > README.md; echo 'print(1)' > app.py
printf 'build:\n\tpython3 -m py_compile app.py && echo BUILD-OK\n' > Makefile
ln -s .env notes; ln -s $H/.ssh/id_ed25519 keylink; ln -s $P/outside/.env outlink
printf '.env\n' > f
# case 33: a .env that was committed and then deleted; git keeps the old copy
mkdir repo33; cd repo33; export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git init -q; G="git -c user.name=t -c user.email=t@example.com"
echo "OLD=FAKE-GITOLD-MARKER-23" > .env; git add -f .env; $G commit -qm one
git rm -q .env; $G commit -qm two
echo SETUP-OK
