#!/usr/bin/env bash

IFACE=wlan1
ifconfig $IFACE down
macchanger -r $IFACE
ifconfig $IFACE up
./env/bin/python3 watcher.py $IFACE
