#!/usr/bin/env bash

ifconfig wlan2 down
macchanger -r wlan2
ifconfig wlan2 up
./env/bin/python3 watcher.py
