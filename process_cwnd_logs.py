import csv
import re

pattern = re.compile(r"(\d+\.\d+):.*bpf_trace_printk: snd_cwnd: (\d+), snd_wnd: (\d+), rcv_wnd: (\d+)")

with open("log_tcp_cwnd.log", "r") as log_file, open("log_tcp_cwnd.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["timestamp_seconds", "snd_cwnd", "snd_wnd", "rcv_wnd"])

    first_timestamp = None
    for line in log_file:
        match = pattern.search(line)
        if not match:
            continue

        timestamp = float(match.group(1))
        if first_timestamp is None:
            first_timestamp = timestamp

        relative_timestamp = int(timestamp - first_timestamp)
        snd_cwnd, snd_wnd, rcv_wnd = match.groups()[1:]
        csv_writer.writerow([relative_timestamp, snd_cwnd, snd_wnd, rcv_wnd])

print("info: logs processed and stored in log_tcp_cwnd.csv")
