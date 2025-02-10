import re
import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

# parse log entries
def parse_log_entry(log_entry):
    # example log entry format: "Jan 24 10:00:00 hostname sshd[1234]: Failed password for invalid user username from 192.168.1.1 port 1234 ssh2"
    pattern = re.compile(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sshd\[\d+\]: (Failed|Accepted) password for (\S+) from (\S+) port \d+ ssh2')
    match = pattern.match(log_entry)
    if match:
        timestamp, hostname, status, username, ip = match.groups()
        current_year = datetime.now().year
        timestamp_with_year = f"{timestamp} {current_year}"
        return {
            'timestamp': datetime.strptime(timestamp_with_year, '%b %d %H:%M:%S %Y'),
            'hostname': hostname,
            'status': status,
            'username': username,
            'ip': ip
        }
    return None

# analyze logs
def analyze_logs(log_entries, threshold=5, time_window=timedelta(minutes=10)):
    failed_attempts = defaultdict(list)
    admin_accounts = {'root', 'admin'}  # example admin accounts

    for entry in log_entries:
        if entry['status'] == 'Failed':
            failed_attempts[entry['ip']].append(entry['timestamp'])

    suspicious_ips = []
    for ip, timestamps in failed_attempts.items():
        if len(timestamps) > threshold:
            for i in range(len(timestamps) - threshold + 1):
                if timestamps[i + threshold - 1] - timestamps[i] <= time_window:
                    suspicious_ips.append(ip)
                    break

    admin_access_attempts = [entry for entry in log_entries if entry['username'] in admin_accounts]

    return suspicious_ips, admin_access_attempts

# report findings
def report_findings(suspicious_ips, admin_access_attempts):
    print("Suspicious IPs with multiple failed login attempts:")
    if suspicious_ips:
        for ip in suspicious_ips:
            print(f"IP: {ip}")
    else:
        print("No suspicious IPs detected.")

    print("\nAdmin account access attempts:")
    if admin_access_attempts:
        for attempt in admin_access_attempts:
            print(f"Timestamp: {attempt['timestamp']}, Username: {attempt['username']}, IP: {attempt['ip']}")
    else:
        print("No admin account access attempts detected.")

# visualize results
def visualize_results(suspicious_ips, admin_access_attempts):
    # visualize suspicious IPs
    if suspicious_ips:
        ip_counts = pd.Series(suspicious_ips).value_counts()
        ip_counts.plot(kind='bar', title='Suspicious IPs with Multiple Failed Login Attempts')
        plt.xlabel('IP Address')
        plt.ylabel('Count')
        plt.show()
    else:
        print("No suspicious IPs to visualize.")

    # visualize admin access attempts
    if admin_access_attempts:
        admin_access_df = pd.DataFrame(admin_access_attempts)
        admin_access_df['timestamp'] = pd.to_datetime(admin_access_df['timestamp'])
        admin_access_df['time'] = admin_access_df['timestamp'].dt.strftime('%H:%M')

        admin_access_df.set_index('timestamp', inplace=True)
        admin_access_df.resample('min').size().plot(kind='line', title='Admin Account Access Attempts Over Time')

        plt.xlabel('Time')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.show()
    else:
        print("No admin account access attempts to visualize.")


#execute the script
def main(log_file_path):
    try:
        with open(log_file_path, 'r') as file:
            log_entries = [parse_log_entry(line) for line in file if parse_log_entry(line)]
    except FileNotFoundError:
        print(f"Error: The file {log_file_path} was not found.")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    suspicious_ips, admin_access_attempts = analyze_logs(log_entries)

    report_findings(suspicious_ips, admin_access_attempts)

    visualize_results(suspicious_ips, admin_access_attempts)


if __name__ == "__main__":
    log_file_path = 'auth.log'  # Log file path
    main(log_file_path)
