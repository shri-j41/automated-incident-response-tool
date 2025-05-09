# Automated Incident Response Tool

This tool is designed to automate the process of monitoring and responding to security incidents on a server. It provides real-time monitoring of various log files, detects suspicious activities, blocks malicious IPs, and generates detailed reports.

## Features

- **Real-time Log Monitoring**: Monitors authentication logs, system logs, Apache access logs, and UFW logs.
- **Attack Detection**: Detects SSH brute-force attacks, file inclusion/path traversal attempts, and command injection attempts.
- **Automated IP Blocking**: Automatically blocks IPs that exceed a defined threshold of failed login attempts or are detected performing malicious activities.
- **Email Alerts**: Sends email notifications for detected attacks and blocked IPs.
- **Detailed Reporting**: Generates and emails detailed security reports.
- **GUI Interface**: Provides a user-friendly GUI for monitoring and managing incidents.

## Requirements

- Python 3.x
- `tkinter` library
- `smtplib` library
- Root privileges for modifying iptables rules

## Installation

1. **Clone the repository**:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the tool**:
    ```sh
    sudo python3 incident_response_tool.py
    ```

## Configuration

### Log File Paths

Update the paths to the log files you want to monitor in the `incident_response_tool.py` file:
```python
AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"
APACHE_LOG_PATH = "/var/log/apache2/access.log"
UFW_LOG_PATH = "/var/log/ufw.log"
```

### Email Configuration

Update the email configuration settings in the `incident_response_tool.py` file:
```python
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "your-email@gmail.com"
EMAIL_RECIPIENT = "recipient-email@gmail.com"
EMAIL_USERNAME = "your-email@gmail.com"
EMAIL_PASSWORD = "your-app-password"
```

### Failed Login Threshold

Set the threshold for failed login attempts before an IP is blocked:
```python
FAILED_LOGIN_THRESHOLD = 3
```

## Usage

1. **Start Monitoring**: Click the "Start Monitoring" button to begin monitoring the log files.
2. **Stop Monitoring**: Click the "Stop Monitoring" button to stop monitoring.
3. **Unblock IP**: Select an IP from the blocked IPs list and click "Unblock Selected IP" to unblock it.
4. **Generate Report**: Click the "Generate Report" button to generate and email a detailed security report.
5. **Force Refresh**: Click the "Force Refresh" button to manually refresh the blocked IPs display.

## Screenshots

![Main Interface](screenshots/main_interface.png)
*Main Interface of the Incident Response Tool*

## Troubleshooting

- **Root Privileges**: Ensure the script is run with root privileges to modify iptables rules.
- **Email Sending Issues**: Verify the email configuration settings and ensure less secure app access is enabled for the sender email account.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Created by Shrijal Esmali
#   a u t o m a t e d - i n c i d e n t - r e s p o n s e - t o o l  
 