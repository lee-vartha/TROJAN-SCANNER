import os
from pathlib import Path

# PATHS
YARA_PATH = "yara64.exe"
RULES_FOLDER = "rules\\trojan_rules.yar"

# VIRUS TOTAL
VT_API_KEY = "34923601df873108e50af7f497e636c88f6087851ca5321dde99cfebec76f509"
VT_URL = "https://www.virustotal.com/api/v3/files/"
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
DELAY = 15 # api rate limit is 1 req per 15 sec

# ------ VERDICT ----------------------------------------------------------------
def decide_verdict(yara_matched: bool, stats: dict = None) -> str:
    if stats and stats.get("malicious", 0) > 0:
        return "Malicious"
    if yara_matched:
        return "Suspicious"
    return "Clean"
# ------------------------------------------------------------------------------
