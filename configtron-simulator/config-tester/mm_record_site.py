import subprocess
from subprocess import Popen, PIPE
import csv
import os
import time
import threading
import sys
from pyvirtualdisplay import Display

if __name__ == "__main__":
	print('url:', sys.argv[1], '| dir:', sys.argv[2])

	display = Display(visible=0, size=(800, 600))
	display.start()

	os_call = ['mm-webrecord', sys.argv[2],  'chromium-browser', '--ignore-certificate-errors', '--user-data-dir=/tmp/nonexistent$(date +%s%N)', sys.argv[1]]
	print(os_call)
	process = subprocess.Popen(os_call, stdout=PIPE, stderr=PIPE, shell=False)
	stdout, stderr = process.communicate()
	print(stdout, stderr)

	display.stop()
