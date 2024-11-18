#!/usr/bin/python3
import csv
import re
from termcolor import colored
import sys

LOG_FILE_PATH = sys.argv[1] if len(sys.argv) > 1 else "tcp_readings.log"
CSV_FILE_PATH = sys.argv[2] if len(sys.argv) > 2 else "tcp_readings.csv"

data = []

first_timestamp = None

with open(LOG_FILE_PATH, "r") as log_file, open(CSV_FILE_PATH, "w") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["timestamp", "snd_cwnd", "snd_wnd", "rcv_wnd", "ssthresh"])

    lines = log_file.readlines()
    for i in range(len(lines)-1):
        if "snd_cwnd" not in lines[i]:
            continue

        line = lines[i].split()
        timestamp = float(line[3][: -1])
        snd_cwnd = int(line[6][: -1])
        snd_wnd = int(line[8][: -1])
        rcv_wnd = int(line[10])
        assert "sshresh" in lines[i+1]
        ssthresh = int(lines[i+1].split()[6])

        if first_timestamp is None:
            first_timestamp = timestamp
        timestamp = int(timestamp - first_timestamp)

        csv_writer.writerow([timestamp, snd_cwnd, snd_wnd, rcv_wnd, ssthresh])

print(f"info: logs processed and stored in '{CSV_FILE_PATH}'")
