from app.honeypots.ftp_honeypot import FTPHoneypot
from app.honeypots.http_honeypot import HTTPHoneypot
from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.telnet_honeypot import TelnetHoneypot

HONEYPOT_TYPES = {
    "FTP": FTPHoneypot,
    "HTTP": HTTPHoneypot,
    "SSH": SSHHoneypot,
    "TELNET": TelnetHoneypot,
}
