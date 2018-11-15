#!/bin/bash
if [ $1 = "primus" ]; then
   echo "trying PRIMUS ..."
   sudo LD_PRELOAD=./wget_hook_tcp.so /usr/local/wget/bin/wget -d --no-hsts -O result/obj.html --no-check-certificate --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9" https://primus.cs.duke.edu/img.jpg
else
  echo "trying given site ..."
  sudo LD_PRELOAD=./wget_hook_tcp.so /usr/local/wget/bin/wget $1 -d --no-hsts -O result/obj.html --no-check-certificate --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9"
fi

