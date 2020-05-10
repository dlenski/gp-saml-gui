#!/bin/bash

set -e

function help
{
echo '
global-protect vpn OPTIONS

Options:
  -u, --url REQUIRED  vpn url
  --help                  Help screen
'
}

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -u|--url)
    VPN_URL="$2"
    shift
    shift
    ;;
    --help)
    help
    exit
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done

set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ "x${VPN_URL}" = "x" ]]; then
  echo "VPN CONNECTION"
  help
  exit 1;
fi
cd /opt/gp-saml-gui/scripts
set +e
./login.sh
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo success
else
  set -e
  sudo rm -rf ~/.vpn.conf
python3 /opt/gp-saml-gui/gp-saml-gui.py --clientos=Windows $VPN_URL > ~/.vpn.conf
source ~/.vpn.conf
python3 /opt/gp-saml-gui/test-globalprotect-login.py --user=${USER} --clientos=Windows -p '' \
         https://redwood.modeln.com/ssl-vpn/login.esp prelogin-cookie=${COOKIE}>login.sh
chmod +x login.sh
./login.sh
fi
