#!/bin/bash

# Copyright (c) 2021 Luigi Tarenga <luigi.tarenga@gmail.com>
# Distributed under the terms of a MIT license.

export LANG=C

if [ ! -f ~/.P100/conf ]; then
  echo missing conf file. plese create a new file $HOME/.P100/conf with content like this example
  echo 'username="username@example.com"'
  echo 'password="pass123"'
  echo 'mac="00:11:22:33:44:55"'
  echo 'lan="192.168.0.0/24"'
  echo 'uuid="11223344-5555-6666-7777-8899aabbccdd"'
  echo
  echo you can generate uuid with this command: cat /proc/sys/kernel/random/uuid
  exit 1
fi

. ~/.P100/conf

if [ ! -f ~/.P100/key.pem ]; then
  echo generating RSA key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out ~/.P100/key.pem
  openssl pkey -in ~/.P100/key.pem -out ~/.P100/pubkey.pem -pubout
fi

ip=$(arp -n | awk '/'"$mac"'/ {print $1}')
if [ -z "$ip" ]; then
  nmap -n -sn $lan; ip=$(arp -n | awk '/'"$mac"'/ {print $1}')
  if [ -z "$ip" ]; then echo cannot find device $mac; exit 1; fi
fi

# HANDSHAKE
if find ~/.P100 -name cookie -mmin +60 | grep -q .; then
  printf -v pubkey "%q" "$(cat ~/.P100/pubkey.pem)"; eval pubkey=${pubkey#$}
  payload='{"method": "handshake", "params": {"key": "'"$pubkey"'"}}'
  curl -s -D ~/.P100/header -o ~/.P100/response -X POST -H "Content-type: application/json" -d "$payload" "http://$ip/app"
  if jq '.error_code == 0' ~/.P100/response | grep -q false; then echo error in handshake; cat ~/.P100/response; echo; exit 1; fi

  jq -r '.result.key' ~/.P100/response | base64 -d | openssl rsautl -decrypt -inkey ~/.P100/key.pem | hexdump -v -e '16/1 "%02x" "\n"' > ~/.P100/aes
  grep -o "TP_SESSIONID[^;]*" ~/.P100/header > ~/.P100/cookie
fi

aeskey=$(head -1 ~/.P100/aes); aesiv=$(tail -1 ~/.P100/aes)
read cookie < ~/.P100/cookie

makerequest() {
  payload=$(echo "$1" | openssl enc -e -aes-128-cbc -K "$aeskey" -iv "$aesiv" -nosalt | base64 -w 0)
  payload='{"method": "securePassthrough", "params": {"request": "'"$payload"'"}}'

  curl -s -o ~/.P100/response -X POST -H "Content-type: application/json" -H "Cookie: $cookie" -d "$payload" "http://$ip/app?token=$token" 
  if jq '.error_code == 0' ~/.P100/response | grep -q false; then echo error in passthrough; cat ~/.P100/response; exit 1; fi

  jq -r '.result.response' ~/.P100/response | base64 -d | openssl enc -d -aes-128-cbc -K "$aeskey" -iv "$aesiv" -nosalt > ~/.P100/response2
  if jq '.error_code == 0' ~/.P100/response2 | grep -q false; then echo error in called method; cat ~/.P100/response2; exit 1; fi
}

# LOGIN
if ! find ~/.P100 -name token -newer ~/.P100/cookie | grep -q .; then
  username=$(printf "$username" | sha1sum | head -c 40 | base64 -w 0)
  password=$(printf "$password" | base64 -w 0)
  makerequest '{"method": "login_device", "params": {"username": "'"$username"'", "password": "'"$password"'"}}'
  jq -r '.result.token' ~/.P100/response2 > ~/.P100/token
fi

read token < ~/.P100/token

case $1 in
 on) makerequest '{"method": "set_device_info", "params": {"device_on": true}}' ;;
 off) makerequest '{"method": "set_device_info", "params": {"device_on": false}}' ;;
 test)
   makerequest '{"method": "'$2'", "params": {"device_on": false}}'
   jq '.result' ~/.P100/response2
 ;;
 info)
   makerequest '{"method": "get_device_info"}'
   jq '.result' ~/.P100/response2
 ;;
 state)
   makerequest '{"method": "get_device_info"}'
   if [ $(jq -r '.result.device_on' ~/.P100/response2) = "true" ]; then echo on; else echo off; fi
 ;;
 *) echo "syntax: $0 {[ on | off | info | state ] <device> | list }" ;;
esac
