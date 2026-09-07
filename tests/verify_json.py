import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    json.load(handle)
print("live JSON smoke test: OK")
