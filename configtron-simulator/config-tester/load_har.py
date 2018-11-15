import subprocess
from subprocess import Popen, PIPE
import os
import sys
from pyvirtualdisplay import Display

if __name__ == "__main__":
	print('url:', sys.argv[1], '| dir:', sys.argv[2])

	display = Display(visible=0, size=(800, 600))
	display.start()

	os_call = ['phantomjs', 'har.js', sys.argv[1], sys.argv[2]]
	process = subprocess.Popen(os_call, stdout=PIPE, stderr=PIPE, shell=False)
	stdout, stderr = process.communicate()
	print(stdout, stderr)

	display.stop()
