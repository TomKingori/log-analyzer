# Log Analyzer

A simple log analysis script that identifies suspicious IP addresses and admin account access attempts in SSH logs.

## Features

- Detects suspicious IPs that have multiple failed login attempts within a short time window.
- Lists admin account access attempts (successful or unsuccessful).
- Visualizes admin account access attempts over time using Matplotlib.

## Requirements

- Python 3.x
- Pandas
- Matplotlib

To install the dependencies, run:

```bash
pip install -r requirements.txt
```

## Files

- `log_analyzer.py`: The main script for log analysis.
- `auth.log`: Example SSH authentication log file to be analyzed.

## Usage

1. Place your SSH log file (e.g., `auth.log`) in the same directory as `log_analyzer.py`.
2. Run the script:

    ```bash
    python log_analyzer.py <path_to_log_file>
    ```

The script will output suspicious IP addresses and admin account access attempts. It will also generate a plot of admin access attempts over time.

## Example

```bash
python log_analyzer.py auth.log
```

The output will display:

- Suspicious IPs (if any) with multiple failed login attempts.
- Admin account access attempts, including timestamps and IP addresses.

Additionally, a plot of admin access attempts will be generated.