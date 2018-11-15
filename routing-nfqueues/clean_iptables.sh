#!/bin/bash
for i in $( sudo iptables -t nat --line-numbers -L | grep ^[0-9] | awk '{ print $1 }' | tac ); do sudo iptables -t nat -D PREROUTING $i; done
sudo iptables -t nat -L --line-numbers
