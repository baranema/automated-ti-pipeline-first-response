#!/usr/bin/env python3
# Print n / mean / stddev / min / max for a results file (one latency per line).

import statistics
import sys

vals = [float(line) for line in open(sys.argv[1]) if line.strip()]
if not vals:
    print("No measurements collected")
    raise SystemExit

print(f"n      = {len(vals)}")
print(f"mean   = {statistics.mean(vals):.2f} s")
if len(vals) > 1:
    print(f"stddev = {statistics.stdev(vals):.2f} s")
print(f"min    = {min(vals):.2f} s")
print(f"max    = {max(vals):.2f} s")
