import tkinter as tk
from tkinter import scrolledtext, simpledialog, Listbox, END, messagebox
import threading
import subprocess
import os
import re
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"
APACHE_LOG_PATH = "/var/log/apache2/access.log"
UFW_LOG_PATH = "/var/log/ufw.log"

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "youremail@gmail.com"  # Replace with your Gmail address
EMAIL_RECIPIENT = "youremxil@gmail.com"  # Replace with the recipient's email address
EMAIL_USERNAME = "youremail@gmail.com"  # Replace with your Gmail address
EMAIL_PASSWORD = "put app password"  # Your App Password

# Set constant for failed login threshold
FAILED_LOGIN_THRESHOLD = 3

# Remove SQL injection patterns
# Remove XSS patterns

FILE_INCLUSION_PATTERNS = [
    r"\.\./\.\./",
    r"/etc/passwd",
    r"c:\\windows\\",
    r"/windows/system",
    r"\.ini$",
    r"boot\.ini",
    r"%00",  # Null byte injection
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*\w+",
    r"\|\s*\w+",
    r"`.*`",
    r"\$\(.*\)",
    r"&\s*\w+",
]

class IncidentResponseTool:
    def __init__(self, root, log_file='incident_response_tool.log', enable_logging=True):
        if root is None:
            root = tk.Tk()  # Create a mock root for testing
            root.withdraw()  # Hide the root window during testing
        self.root = root
        self.root.title("Automated Incident Response Tool")
        
        # Configure logging first
        if enable_logging:
            logging.basicConfig(filename=log_file, level=logging.DEBUG,
                              format='%(asctime)s - %(levelname)s - %(message)s')
        
        logging.info("Starting Incident Response Tool")
        
        # Create the main UI components
        self.log_display = scrolledtext.ScrolledText(root, width=100, height=30)
        self.log_display.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        # Add a frame for buttons
        button_frame = tk.Frame(root)
        button_frame.pack(fill=tk.X, pady=5)
        
        self.start_stop_button = tk.Button(button_frame, text="Start Monitoring", 
                                         command=self.toggle_monitoring, width=15)
        self.start_stop_button.pack(side=tk.LEFT, padx=5)

        self.unblock_button = tk.Button(button_frame, text="Unblock Selected IP", 
                                      command=self.unblock_ip, width=15)
        self.unblock_button.pack(side=tk.LEFT, padx=5)

        self.generate_report_button = tk.Button(button_frame, text="Generate Report", 
                                             command=self.generate_report, width=15)
        self.generate_report_button.pack(side=tk.LEFT, padx=5)
        
        # Removed refresh button
        
        # Add a frame for the blocked IPs list with better organization
        ip_frame = tk.LabelFrame(root, text="Blocked IPs")
        ip_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Add a scrollbar to the IP listbox
        ip_scroll = tk.Scrollbar(ip_frame)
        ip_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.blocked_ips_listbox = Listbox(ip_frame, height=6, width=50, 
                                        yscrollcommand=ip_scroll.set)
        self.blocked_ips_listbox.pack(fill=tk.X, padx=5, pady=5, expand=True)
        ip_scroll.config(command=self.blocked_ips_listbox.yview)
        
        # Initialize state variables
        self.failed_login_attempts = {}
        self.blocked_ips = set()
        self.monitoring = False
        self.monitor_thread = None
        self.lock = threading.Lock()  # Shared lock for thread safety

        self.log_positions = {
            AUTH_LOG_PATH: 0,
            SYSLOG_PATH: 0,
            APACHE_LOG_PATH: 0,
            UFW_LOG_PATH: 0
        }

        # Add web attack counters
        self.ssh_attack_count = 0  # Corrected attribute name
        self.file_inclusion_count = 0
        self.command_injection_count = 0

        # Add a frame for tracking different types of attacks
        attack_frame = tk.LabelFrame(root, text="Attack Statistics")
        attack_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Create a frame for attack counters
        stats_frame = tk.Frame(attack_frame)
        stats_frame.pack(fill=tk.X, pady=2)
        
        # Add counters for different attack types
        self.ssh_attacks_var = tk.StringVar(value="SSH Attacks: 0")  # Corrected attribute name
        self.file_attacks_var = tk.StringVar(value="Path Traversal: 0")
        self.cmd_attacks_var = tk.StringVar(value="CMD Injection: 0")
        
        ssh_label = tk.Label(stats_frame, textvariable=self.ssh_attacks_var, width=20)  # Corrected attribute name
        ssh_label.pack(side=tk.LEFT, padx=10)
        
        file_label = tk.Label(stats_frame, textvariable=self.file_attacks_var, width=20)
        file_label.pack(side=tk.LEFT, padx=10)
        
        cmd_label = tk.Label(stats_frame, textvariable=self.cmd_attacks_var, width=20)
        cmd_label.pack(side=tk.LEFT, padx=10)

        # Add the label at the bottom center
        self.footer_label = tk.Label(root, text="Created By Shrijal Esmali")
        self.footer_label.pack(side=tk.BOTTOM, pady=10)
        
        # Initialize the app state
        try:
            self.update_log_display("Initializing Incident Response Tool...")
            self.clear_state()  # Clear previous state and load blocked IPs
            self.reset_log_positions()  # Reset log positions to the end of the log files
            self.update_log_display("Initialization complete. Ready to monitor.")
        except Exception as e:
            logging.error(f"Initialization error: {str(e)}")
            self.update_log_display(f"ERROR: {str(e)}")
            messagebox.showerror("Initialization Error", f"An error occurred during initialization: {str(e)}")

        # Add a force refresh button for debugging
        self.refresh_button = tk.Button(button_frame, text="Force Refresh", 
                                      command=self.force_refresh_display, width=15)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

    # Remove the test_block_ip method
    
    # ... rest of methods with correct indentation ...
    def reset_log_positions(self):
        """Reset the file pointers to the end of all log files"""
        for log_path in self.log_positions.keys():
            try:
                with open(log_path, 'r') as file:
                    file.seek(0, os.SEEK_END)
                    self.log_positions[log_path] = file.tell()
                    logging.debug(f"Reset log position for {log_path} to {file.tell()}")
            except FileNotFoundError:
                logging.error(f"Log file not found: {log_path}")
                self.update_log_display(f"Warning: Log file not found: {log_path}")
            except Exception as e:
                logging.error(f"Error reading log: {e}")
                self.update_log_display(f"Error reading log: {e}")

    def toggle_monitoring(self):
        """Start or stop the log monitoring thread"""
        if self.monitoring:
            self.monitoring = False
            self.start_stop_button.config(text="Start Monitoring")
            self.update_log_display("Monitoring stopped.")
        else:
            self.monitoring = True
            self.start_stop_button.config(text="Stop Monitoring")
            self.update_log_display("Monitoring started...")
            
            # Ensure blocked IPs are displayed when monitoring starts
            self._ensure_ips_in_listbox()
            
            self.monitor_thread = threading.Thread(target=self.monitor_logs)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def monitor_logs(self):
        """Main monitoring loop that checks all log files periodically"""
        while self.monitoring:
            try:
                # Debug info to help track state
                logging.debug(f"Current blocked IPs: {self.blocked_ips}")
                
                # Ensure blocked IPs are reflected in listbox
                self._ensure_ips_in_listbox()
                
                # Check each log file
                self.check_auth_log(AUTH_LOG_PATH)
                self.check_syslog(SYSLOG_PATH)
                self.check_apache_log(APACHE_LOG_PATH)
                self.check_ufw_log(UFW_LOG_PATH)
                
            except Exception as e:
                logging.error(f"Error monitoring logs: {e}")
                self.update_log_display(f"Error during monitoring: {e}")
            time.sleep(5)  # Check logs every 5 seconds

    def check_auth_log(self, path):
        self._check_log(path, self._process_auth_log_line)

    def check_syslog(self, path):
        self._check_log(path, self._process_syslog_line)

    def check_apache_log(self, path):
        self._check_log(path, self._process_apache_log_line)

    def check_ufw_log(self, path):
        self._check_log(path, self._process_ufw_log_line)

    def _check_log(self, path, process_line_func):
        """Generic log file reading function"""
        try:
            with open(path, 'r') as file:
                file.seek(self.log_positions.get(path, 0))
                for line in file:
                    logging.debug(f"Processing line: {line.strip()}")
                    process_line_func(line)
                self.log_positions[path] = file.tell()
        except FileNotFoundError:
            # Only log this once, not repeatedly
            if self.log_positions.get(path, 0) == 0:
                logging.error(f"Log file not found: {path}")
        except Exception as e:
            logging.error(f"Error reading log: {e}")

    def _process_auth_log_line(self, line):
        """Process authentication log entries, focusing on SSH failures"""
        logging.debug(f"Processing auth log line: {line.strip()}")
        
        # Check for SSH failures with more specific pattern matching
        if "Failed password" in line and ("ssh" in line.lower() or "sshd" in line.lower()):
            ip = self.extract_ip(line)
            if ip:
                with self.lock:
                    # Update SSH attack counter
                    self.ssh_attack_count += 1  # Corrected attribute name
                    # Update GUI in main thread
                    self.root.after(0, lambda: self.ssh_attacks_var.set(f"SSH Attacks: {self.ssh_attack_count}"))
                    
                    # Only track attempts if the IP is not already blocked
                    if ip not in self.blocked_ips:
                        self.failed_login_attempts[ip] = self.failed_login_attempts.get(ip, 0) + 1
                        attempts = self.failed_login_attempts[ip]
                        self.update_log_display(f"Failed login attempts for {ip}: {attempts}")
                        logging.info(f"Failed login attempts for {ip}: {attempts}")
                        
                        # Block IP when threshold is reached
                        if attempts >= FAILED_LOGIN_THRESHOLD:
                            self.update_log_display(f"Threshold reached ({FAILED_LOGIN_THRESHOLD}): Blocking IP {ip}...")
                            self.block_ip(ip)
                    else:
                        # IP is already blocked, just log the attempt
                        self.update_log_display(f"Blocked IP {ip} attempted login")
                        logging.info(f"Blocked IP {ip} attempted login")
                
            else:
                # For failures without an IP, show a specific message
                self.update_log_display("Authentication failure detected but could not extract IP.")
                logging.warning(f"Authentication failure detected but could not extract IP: {line.strip()}")
            
            # Display the original log line
            self.update_log_display(line.strip())
        
        # Enhanced detection for sudo authentication failures
        elif "sudo" in line and (
            "authentication failure" in line.lower() or 
            "incorrect password attempt" in line.lower() or 
            "3 incorrect password attempts" in line.lower() or
            "failed password" in line.lower() or
            "pam_unix" in line.lower() and "authentication failure" in line.lower()
        ):
            self.update_log_display("⚠️ Sudo authentication failure detected!")
            ip = self.extract_ip(line)
            if ip:
                with self.lock:
                    # Only track attempts if the IP is not already blocked
                    if ip not in self.blocked_ips:
                        self.failed_login_attempts[ip] = self.failed_login_attempts.get(ip, 0) + 1
                        attempts = self.failed_login_attempts[ip]
                        self.update_log_display(f"Failed sudo attempts for {ip}: {attempts}")
                        logging.info(f"Failed sudo attempts for {ip}: {attempts}")
                        
                        if attempts >= FAILED_LOGIN_THRESHOLD:
                            self.update_log_display(f"Threshold reached ({FAILED_LOGIN_THRESHOLD}): Blocking IP {ip}...")
                            self.block_ip(ip)
                    else:
                        # IP is already blocked, just log the attempt
                        self.update_log_display(f"Blocked IP {ip} attempted sudo access")
                        logging.info(f"Blocked IP {ip} attempted sudo access")
            else:
                self.update_log_display("Sudo authentication failure detected (no IP found).")
            
            # Display the original log line
            self.update_log_display(line.strip())

    def _process_syslog_line(self, line):
        logging.debug(f"Processing syslog line: {line.strip()}")
        self.update_log_display(line.strip())

    def _process_apache_log_line(self, line):
        """Process apache log entries with web attack detection"""
        logging.debug(f"Processing apache log line: {line.strip()}")
        
        # Extract IP address from the log line
        ip = self.extract_ip(line)
        
        # URL decode the line to catch encoded attacks
        decoded_line = self._url_decode(line)
        
        # Check for various web attacks
        attack_found = False
        
        # Check for file inclusion/path traversal
        if self.detect_file_inclusion(decoded_line):
            self.update_log_display(f"⚠️ Path Traversal attempt detected: {line.strip()}")
            logging.warning(f"Path Traversal attempt detected: {line.strip()}")
            
            # Update file inclusion counter and display
            with self.lock:
                self.file_inclusion_count += 1
                self.file_attacks_var.set(f"Path Traversal: {self.file_inclusion_count}")
            
            attack_found = True
            attack_type = "Path Traversal"
            
        # Check for command injection
        elif self.detect_command_injection(decoded_line):
            self.update_log_display(f"⚠️ Command Injection attempt detected: {line.strip()}")
            logging.warning(f"Command Injection attempt detected: {line.strip()}")
            
            # Update command injection counter and display
            with self.lock:
                self.command_injection_count += 1
                self.cmd_attacks_var.set(f"CMD Injection: {self.command_injection_count}")
            
            attack_found = True
            attack_type = "Command Injection"
            
        # If any attack was found and we have an IP, block it
        if attack_found and ip and ip not in self.blocked_ips:
            self.update_log_display(f"Blocking IP {ip} for {attack_type} attempt")
            self.block_ip(ip)
            
            # Send alert email
            self.send_email(
                f"Security Alert: {attack_type} Attempt", 
                f"A {attack_type} attack was detected from IP: {ip}\n\nLog entry:\n{line}"
            )
        elif attack_found:
            self.update_log_display(f"{attack_type} detected, but couldn't extract IP or IP already blocked")
        else:
            # Just display the regular log line
            self.update_log_display(line.strip())

    def _process_ufw_log_line(self, line):
        logging.debug(f"Processing ufw log line: {line.strip()}")
        if "BLOCK" in line:
            self.update_log_display(line.strip())
            
            # Extract IP from UFW block messages and add to our blocked list if not there already
            ip = self.extract_ip(line)
            if ip and ip not in self.blocked_ips:
                with self.lock:
                    self.blocked_ips.add(ip)
                    self.blocked_ips_listbox.insert(END, ip)
                    self.update_log_display(f"Added previously blocked IP to tracking: {ip}")

    def extract_ip(self, line):
        """Extract IP addresses from log lines with improved pattern matching"""
        # Enhanced IP extraction that looks specifically for SSH patterns first
        ssh_pattern = r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ssh_pattern, line)
        if match:
            return match.group(1)
        
        # UFW specific pattern
        ufw_pattern = r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ufw_pattern, line)
        if match:
            return match.group(1)
        
        # Fallback to general IP detection
        general_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(general_pattern, line)
        return match.group(0) if match else None

    def send_email(self, subject, body, attachment_path=None):
        """Send email alerts"""
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        if attachment_path and os.path.exists(attachment_path):
            try:
                with open(attachment_path, 'r') as attachment:
                    part = MIMEText(attachment.read(), 'plain')
                    part.add_header('Content-Disposition', 'attachment', 
                                   filename=os.path.basename(attachment_path))
                    msg.attach(part)
            except Exception as e:
                logging.error(f"Error attaching file {attachment_path}: {e}")

        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            text = msg.as_string()
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, text)
            server.quit()
            logging.info(f"Email sent: {subject}")
            return True
        except Exception as e:
            logging.error(f"Error sending email: {e}")
            self.update_log_display(f"Failed to send email: {e}")
            return False

    def block_ip(self, ip):
        """Block an IP using iptables"""
        # Check if IP is already in our block list to prevent duplicates
        if ip in self.blocked_ips:
            logging.info(f"IP {ip} is already blocked, skipping")
            self.update_log_display(f"IP {ip} is already in blocked list")
            return
            
        try:
            logging.info(f"Executing iptables to block IP: {ip}")
            self.update_log_display(f"Blocking IP: {ip}")
            
            # First try with sudo for systems where script isn't running as root
            try:
                result = subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # If sudo fails, try direct command (assuming running as root)
                result = subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
            
            logging.debug(f"iptables command executed, returncode: {result.returncode}")
            
            # Update our internal tracking
            with self.lock:
                # Add to blocked IPs set
                self.blocked_ips.add(ip)
                
                # Reset failed login attempts counter for this IP since it's now blocked
                if ip in self.failed_login_attempts:
                    self.failed_login_attempts.pop(ip)
            
            # DIRECT GUI UPDATE - this is the critical fix
            # Add to listbox directly in the main thread, not through root.after which might be unreliable
            self.update_log_display(f"Updating blocked IPs listbox with {ip}")
            
            # Check if IP is already in the listbox before adding
            existing_ips = list(self.blocked_ips_listbox.get(0, END))
            if ip not in existing_ips:
                self.blocked_ips_listbox.insert(END, ip)
                self.blocked_ips_listbox.see(END)
                
            self.update_log_display(f"✓ Successfully blocked IP: {ip}")
            self.update_log_display(f"Total blocked IPs: {len(self.blocked_ips)}")
            
            # Force a UI refresh to ensure changes are visible
            self.root.update_idletasks()
            
            # Send email notification
            self.send_email(
                "Security Alert: IP Blocked", 
                f"The IP {ip} has been blocked after {FAILED_LOGIN_THRESHOLD} failed login attempts."
            )
                
        except Exception as e:
            logging.error(f"Error in block_ip function: {str(e)}")
            self.update_log_display(f"⚠ Error blocking IP {ip}: {str(e)}")

    def unblock_ip(self, ip=None):
        """Unblock a previously blocked IP"""
        # If no IP provided, use the selected one from listbox
        if ip is None:
            if not self.blocked_ips_listbox.curselection():
                self.update_log_display("No IP selected for unblocking")
                messagebox.showinfo("No Selection", "Please select an IP to unblock from the list")
                return
                
            index = self.blocked_ips_listbox.curselection()[0]
            selected_ip = self.blocked_ips_listbox.get(index)
            logging.debug(f"Selected IP to unblock: {selected_ip} at index {index}")
        else:
            selected_ip = ip
        
        self.update_log_display(f"Attempting to unblock IP: {selected_ip}")
        
        # Check if the IP is in our blocked list
        if selected_ip in self.blocked_ips:
            try:
                logging.info(f"Executing iptables to unblock IP: {selected_ip}")
                self.update_log_display(f"Running: iptables -D INPUT -s {selected_ip} -j DROP")
                
                # Try with sudo first
                try:
                    result = subprocess.run(
                        ["sudo", "iptables", "-D", "INPUT", "-s", selected_ip, "-j", "DROP"], 
                        check=True, capture_output=True, text=True, timeout=5
                    )
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    # If sudo fails, try direct command (assuming running as root)
                    result = subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", selected_ip, "-j", "DROP"], 
                        check=True, capture_output=True, text=True, timeout=5
                    )
                
                # Verify the block was removed
                verify_result = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", selected_ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=5
                )
                
                # A non-zero return code means the rule doesn't exist (successfully removed)
                if verify_result.returncode != 0:
                    # Update our internal tracking
                    with self.lock:
                        self.blocked_ips.remove(selected_ip)
                        self.failed_login_attempts.pop(selected_ip, None)  # Also reset failed attempts
                        
                        # Update listbox - find and remove the IP
                        for i in range(self.blocked_ips_listbox.size()):
                            if self.blocked_ips_listbox.get(i) == selected_ip:
                                self.blocked_ips_listbox.delete(i)
                                break
                    
                    self.update_log_display(f"✓ Successfully unblocked IP: {selected_ip}")
                    self.send_email("IP Unblocked", f"The IP {selected_ip} has been manually unblocked.")
                else:
                    self.update_log_display(f"⚠ Failed to verify unblock for IP {selected_ip}")
                    logging.error(f"Failed to verify unblock for IP {selected_ip}")
                
            except Exception as e:
                logging.error(f"Error unblocking IP {selected_ip}: {str(e)}")
                self.update_log_display(f"⚠ Error unblocking IP {selected_ip}: {str(e)}")
                messagebox.showerror("Error", f"Failed to unblock IP: {str(e)}")
        else:
            logging.warning(f"IP {selected_ip} is not in the blocked list")
            self.update_log_display(f"IP {selected_ip} is not in the blocked list")
            messagebox.showinfo("Not Blocked", f"IP {selected_ip} is not currently blocked")

    def clear_log_display(self):
        """Clear the log display text box"""
        self.log_display.delete(1.0, tk.END)

    def update_log_display(self, message):
        """Update the GUI log display with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_display.yview(tk.END)  # Auto-scroll to the end
        
        # Make sure UI updates happen immediately, even during heavy processing
        self.root.update_idletasks()

    def generate_report(self):
        """Generate a detailed security report"""
        report_lines = []
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        report_lines.append(f"Incident Response Report - {timestamp}\n")
        report_lines.append("="*50 + "\n\n")
        
        # Add attack statistics
        report_lines.append("Attack Statistics:\n")
        report_lines.append(f"- SSH Attack Attempts: {self.ssh_attack_count}\n")
        report_lines.append(f"- Path Traversal Attempts: {self.file_inclusion_count}\n")
        report_lines.append(f"- Command Injection Attempts: {self.command_injection_count}\n\n")
        
        report_lines.append("Blocked IPs:\n")
        if self.blocked_ips:
            for ip in self.blocked_ips:
                report_lines.append(f"- {ip}\n")
        else:
            report_lines.append("No IPs currently blocked.\n")
        
        report_lines.append("\nFailed Login Attempts:\n")
        if self.failed_login_attempts:
            for ip, attempts in self.failed_login_attempts.items():
                report_lines.append(f"- {ip}: {attempts} attempts\n")
        else:
            report_lines.append("No failed login attempts recorded.\n")
        
        report_lines.append("\nMonitored Log Files:\n")
        for log_path, position in self.log_positions.items():
            report_lines.append(f"- {log_path}: {position} bytes read\n")
        
        report_content = "".join(report_lines)
        
        report_file_path = "incident_response_report.txt"
        try:
            with open(report_file_path, 'w') as report_file:
                report_file.write(report_content)
            
            self.update_log_display(f"Report generated: {os.path.abspath(report_file_path)}")
            
            # Send the report via email
            email_sent = self.send_email(
                "Incident Response Report", 
                "Please find the attached incident response report.", 
                report_file_path
            )
            
            if email_sent:
                self.update_log_display("Report sent via email.")
                messagebox.showinfo("Report Generated", 
                                   f"Report generated and saved to {report_file_path}.\nReport also sent via email.")
            else:
                self.update_log_display("Report generated but email sending failed.")
                messagebox.showinfo("Report Generated", 
                                   f"Report generated and saved to {report_file_path}.\nEmail sending failed.")
                
        except Exception as e:
            logging.error(f"Error generating report: {e}")
            self.update_log_display(f"Error generating report: {e}")
            messagebox.showerror("Error", f"Failed to generate report: {e}")

    def clear_state(self):
        """Reset application state and reload blocked IPs from iptables"""
        self.failed_login_attempts = {}
        self.blocked_ips = set()
        
        # Reset attack counters
        self.ssh_attack_count = 0
        self.file_inclusion_count = 0
        self.command_injection_count = 0
        
        # Update display counters
        self.ssh_attacks_var.set(f"SSH Attacks: {self.ssh_attack_count}")
        self.file_attacks_var.set(f"Path Traversal: {self.file_inclusion_count}")
        self.cmd_attacks_var.set(f"CMD Injection: {self.command_injection_count}")
        
        self.log_positions = {
            AUTH_LOG_PATH: 0,
            SYSLOG_PATH: 0,
            APACHE_LOG_PATH: 0,
            UFW_LOG_PATH: 0
        }
        
        # Clear and reload the blocked IPs listbox
        self.blocked_ips_listbox.delete(0, END)
        
        # Load existing blocked IPs from iptables
        self.load_blocked_ips()

    def load_blocked_ips(self):
        """Load currently blocked IPs from iptables"""
        try:
            self.update_log_display("Loading blocked IPs from iptables...")
            
            try:
                # Try with sudo first
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "INPUT", "-n"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # If sudo fails, try direct command (assuming running as root)
                result = subprocess.run(
                    ["iptables", "-L", "INPUT", "-n"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
                
            lines = result.stdout.split('\n')
            
            ips_found = 0
            for line in lines:
                # Look for DROP rules with IP addresses
                if "DROP" in line:
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if match:
                        ip = match.group(1)
                        if ip not in self.blocked_ips:
                            self.blocked_ips.add(ip)
                            # Make sure to update GUI in the main thread
                            self.root.after(0, lambda ip=ip: self.blocked_ips_listbox.insert(END, ip))
                            ips_found += 1
                            
                            # Make sure this IP doesn't have failed login attempts tracked
                            # since it's already blocked
                            if ip in self.failed_login_attempts:
                                self.failed_login_attempts.pop(ip)
            
            self.update_log_display(f"Loaded {ips_found} blocked IPs from iptables")
            logging.info(f"Current blocked IPs: {self.blocked_ips}")
            
            # Force refresh of the listbox after loading to ensure consistency
            self.refresh_blocked_ips_display()
            
        except Exception as e:
            logging.error(f"Error loading blocked IPs: {str(e)}")
            self.update_log_display(f"Error loading blocked IPs: {str(e)}")

    def _verify_blocked_ips_consistency(self):
        """Verify that blocked_ips set is consistent with the listbox display"""
        listbox_ips = set(self.blocked_ips_listbox.get(0, END))
        
        # Check if any IPs are in the set but not in the listbox
        for ip in self.blocked_ips:
            if ip not in listbox_ips:
                logging.warning(f"IP {ip} is in blocked_ips but not in listbox, fixing...")
                self.blocked_ips_listbox.insert(END, ip)
        
        # Check if any IPs are in the listbox but not in the set
        for ip in listbox_ips:
            if ip not in self.blocked_ips:
                logging.warning(f"IP {ip} is in listbox but not in blocked_ips, fixing...")
                # Find and remove the IP from the listbox
                for i in range(self.blocked_ips_listbox.size()):
                    if self.blocked_ips_listbox.get(i) == ip:
                        self.blocked_ips_listbox.delete(i)
                        break

    def _synchronize_blocked_ips_list(self):
        """Ensure the blocked IPs listbox is in sync with the blocked_ips set"""
        with self.lock:
            # Get current listbox contents
            listbox_ips = set(self.blocked_ips_listbox.get(0, END))
            
            # Add any missing IPs to the listbox
            for ip in self.blocked_ips:
                if ip not in listbox_ips:
                    logging.info(f"Adding missing IP {ip} to listbox")
                    self.blocked_ips_listbox.insert(END, ip)
                    
            # Remove any IPs from the listbox that aren't in blocked_ips
            for i in range(self.blocked_ips_listbox.size()-1, -1, -1):
                ip = self.blocked_ips_listbox.get(i)
                if ip not in self.blocked_ips:
                    logging.info(f"Removing IP {ip} from listbox that's not in blocked_ips set")
                    self.blocked_ips_listbox.delete(i)

    def _ensure_ips_in_listbox(self):
        """Make sure all blocked IPs appear in the listbox (lightweight version)"""
        try:
            # Get current listbox contents
            listbox_ips = set(self.blocked_ips_listbox.get(0, END))
            
            # Add any missing IPs to the listbox
            for ip in self.blocked_ips:
                if ip not in listbox_ips:
                    self.blocked_ips_listbox.insert(END, ip)
        except Exception as e:
            logging.error(f"Error while ensuring IPs in listbox: {str(e)}")

    def refresh_blocked_ips_display(self):
        """Force a refresh of the blocked IPs display"""
        self.update_log_display("Refreshing blocked IPs display...")
        
        # Clear the listbox
        self.blocked_ips_listbox.delete(0, END)
        
        # Re-add all IPs from the set
        for ip in sorted(self.blocked_ips):
            self.blocked_ips_listbox.insert(END, ip)
        
        # Also check iptables for any IPs we might have missed
        try:
            try:
                # Try with sudo first
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "INPUT", "-n"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # If sudo fails, try direct command (assuming running as root)
                result = subprocess.run(
                    ["iptables", "-L", "INPUT", "-n"], 
                    check=True, capture_output=True, text=True, timeout=5
                )
            
            for line in result.stdout.split('\n'):
                if "DROP" in line:
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if match:
                        ip = match.group(1)
                        if ip not in self.blocked_ips:
                            self.blocked_ips.add(ip)
                            self.blocked_ips_listbox.insert(END, ip)
                            self.update_log_display(f"Found new blocked IP: {ip}")
            
        except Exception as e:
            logging.error(f"Error refreshing blocked IPs from iptables: {str(e)}")
            self.update_log_display(f"Error checking iptables: {str(e)}")
        
        self.update_log_display(f"Displaying {self.blocked_ips_listbox.size()} blocked IPs")

    def detect_file_inclusion(self, line):
        """Check if a log line contains file inclusion/path traversal attempts"""
        for pattern in FILE_INCLUSION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def detect_command_injection(self, line):
        """Check if a log line contains command injection attempts"""
        for pattern in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    # Add this new method to ensure the GUI is initialized with blocked IPs
    def initialize_blocked_ips(self):
        """Make sure all blocked IPs are displayed in the listbox on startup"""
        # Clear the listbox first to avoid duplicates
        self.blocked_ips_listbox.delete(0, END)
        
        # Add all IPs from the set
        for ip in sorted(self.blocked_ips):
            self.blocked_ips_listbox.insert(END, ip)
            
        # Log the current state
        logging.info(f"Initialized blocked IPs display with {len(self.blocked_ips)} IPs")
        self.update_log_display(f"Displaying {len(self.blocked_ips)} blocked IPs")

    # Add this missing method that's needed for URL decoding
    def _url_decode(self, text):
        """URL decode a string to catch encoded attacks"""
        try:
            import urllib.parse
            return urllib.parse.unquote(text)
        except:
            return text  # Return original if decoding fails

    # Add this method to force an immediate refresh of the display
    def force_refresh_display(self):
        """Force a complete refresh of the blocked IPs display"""
        self.update_log_display("Forcing display refresh...")
        
        # First clear the listbox
        self.blocked_ips_listbox.delete(0, END)
        
        # Then add all blocked IPs directly
        for ip in sorted(self.blocked_ips):
            self.blocked_ips_listbox.insert(END, ip)
        
        # Log the action
        self.update_log_display(f"Display refreshed with {len(self.blocked_ips)} IPs")
        
        # Force the GUI to update
        self.root.update_idletasks()

if __name__ == "__main__":
    # Add signal handler for graceful shutdown
    import signal
    import sys
    
    def signal_handler(sig, frame):
        print("\nShutting down gracefully...")
        try:
            app.monitoring = False  # Stop monitoring if running
            print("Monitoring stopped")
        except:
            pass
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C handler
    
    # Check if running as root - essential for iptables
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: This script should be run as root for iptables functionality.")
        print("Try running with: sudo python3 incident_response_tool.py")
        # Continue anyway for testing purposes, but show a warning
        root = tk.Tk()
        messagebox.showwarning(
            "Root Privileges Required",
            "This tool requires root privileges to modify iptables rules.\n"
            "Some functionality might not work correctly."
        )
    else:
        root = tk.Tk()
    
    # Set window size and position
    root.geometry("900x700")
    root.minsize(800, 600)
    
    # Start the application
    app = IncidentResponseTool(root)
    
    # Explicitly initialize the blocked IPs display
    app.initialize_blocked_ips()
    
    # Make sure blocked IPs are displayed at startup
    app._ensure_ips_in_listbox()
    
    # Force the display to show blocked IPs immediately after startup
    app.force_refresh_display()
    
    # Handle window close event
    def on_closing():
        try:
            app.monitoring = False  # Stop monitoring if running
            logging.info("Application closing - shutting down monitoring")
            print("Application closed by user")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
        finally:
            root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
