#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <target_ip>"
  exit 1
fi

TARGET=$1
BASE_DIR="scan_$TARGET"

mkdir -p $BASE_DIR/{nmap,web}

function fast_scan() {
  echo "[+] Fast port scan"
  nmap -Pn -T4 --open $TARGET -oN $BASE_DIR/nmap/fast.txt
}

function full_scan() {
  echo "[+] Full TCP scan"
  nmap -Pn -p- -T4 $TARGET -oN $BASE_DIR/nmap/full.txt
}

function service_scan() {
  echo "[+] Service and default scripts scan"
  nmap -Pn -sC -sV $TARGET -oN $BASE_DIR/nmap/services.txt
}

function web_scan() {
  echo "[+] Web reconnaissance"

  for port in 80 443; do
    if grep -q "$port/tcp" $BASE_DIR/nmap/*.txt 2>/dev/null; then
      echo "[+] Port $port detected, scanning web"

      whatweb http://$TARGET:$port \
        | tee -a $BASE_DIR/web/whatweb.txt

      feroxbuster \
        -u http://$TARGET:$port \
        -w /usr/share/wordlists/dirb/common.txt \
        -o $BASE_DIR/web/dirs_$port.txt
    fi
  done
}

while true; do
  echo ""
  echo "==== HTB Scan Menu ===="
  echo "1) Fast scan (top ports)"
  echo "2) Full TCP scan"
  echo "3) Service + scripts scan"
  echo "4) Web scan (80/443)"
  echo "5) Run ALL"
  echo "0) Exit"
  echo "======================="
  read -p "Choice: " choice

  case $choice in
    1) fast_scan ;;
    2) full_scan ;;
    3) service_scan ;;
    4) web_scan ;;
    5)
       fast_scan
       full_scan
       service_scan
       web_scan
       ;;
    0) exit 0 ;;
    *) echo "Invalid choice" ;;
  esac
done


# chmod +x bigscan.sh
# ./bigscan.sh 10.10.11.123
