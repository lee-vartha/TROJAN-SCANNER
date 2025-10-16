import base64, os, random, string, time, shutil, tempfile

try:
	import requests
except Exception:
	requests = None

TMP_DIR = os.path.join(tempfile.gettempdir(), "SystemCache-BENIGN")
os.makedirs(TMP_DIR, exist_ok=True)

UA_OBF = base64.b64encode(b"BenignClient/1.0").decode()
LOCAL_BEACON = "http://127.0.0.1:8000/ping"

def random_name(n=8):
	return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def write_dummy():
	path = os.path.join(TMP_DIR, f"{random_name()}.dat")
	with open(path, "wb") as f:
		f.write(os.urandom(2048))
	return path

def maybe_beacon():
	if not requests:
		return
	try:
		headers = {"User-Agent": base64.b64decode(UA_OBF).decode()}
		requests.get(LOCAL_BEACON, headers=headers, timeout=1)
	except Exception:
		pass

def housekeep(max_files=30):
	files = sorted(
		(os.path.join(TMP_DIR, f) for f in os.listdir(TMP_DIR)),
		key=lambda p: os.path.getmtime(p),
	)
	for p in files[:-max_files]:
		try: os.remove(p)
		except Exception: pass

def main():
	i = 0
	while True:
		i += 1
		p = write_dummy()
		maybe_beacon()
		if i % 10 == 0:
			housekeep()
		time.sleep(0.75)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		try: shutil.rmtree(TMP_DIR, ignore_errors=True)
		except Exception: pass
		print("\nStopped and cleaned.")