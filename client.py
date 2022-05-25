import sys
import time
import requests
import hashlib
import hmac
uplink = "http://10.0.1.14"

if len(sys.argv) == 1:
	print("need at least 1 argument")
	exit(1)

command = sys.argv[1]
data = sys.argv[2] if len(sys.argv) == 3 else None

with open("secrets.h") as credfile:
    down_key = [line.split('"')[1] for line in credfile if "DOWN_COMMAND_KEY" in line][0]

t = int(time.time()) * 1000
payload = f"{t};{command};"

if data is not None:
	payload += f"{data};"

hash = hmac.new(down_key.encode("utf8"), payload.encode("utf8"), hashlib.sha256).hexdigest().upper()
print(hash)
r = requests.post(uplink, payload, headers={"HMAC": hash})
print(r.text)
