#/bin/bash
sudo iptables -t nat -A PREROUTING -p tcp -j NFQUEUE --queue-num 1
