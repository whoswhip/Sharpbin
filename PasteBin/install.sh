#!/bin/bash
############################################
####      Sharpbin Linux installer      ####
############################################
##
##	This is a semi completed script to install Sharpbin on Linux, however it does not set it as a system daemon/service, cause idk how to do that lol
##

mkdir sharpbin
cd sharpbin

curl -s "https://api.github.com/repos/whoswhip/Sharpbin/releases/latest" | jq -r '.assets[] | select(.name | test("sharpbin-linux-.*\\.tar$")) | .browser_download_url' | xargs -I {} curl -L -o sharpbin-linux.tar {}

tar -xvf sharpbin-linux.tar
chmod +x Sharpbin

echo "Enter your cloudflare sitekey: "
read sitekey
echo "Enter your cloudflare secretkey: "
read secretkey


echo "{ \"CF_TurnstileSiteKey\": \"$sitekey\", \"CF_TurnstileSecret\": \"$secretkey\" }" > config.json 
