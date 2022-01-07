# P100.sh
shell script to control TP-Link P100 smart plug

this script have some dependencies, openssl, nmap, curl.
the syntax is simple as:
./P100.sh on
./P100.sh off
./P100.sh info
./P100.sh state

if you need to drive more than one device you will need to change the code to add support for it.
for example you will have to add some token and cookie on a per-device base and pass the MAC as parameter
to on / off function
