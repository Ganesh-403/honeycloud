from app.honeypots.ftp_honeypot import FTPHoneypot
from app.honeypots.http_honeypot import HTTPHoneypot
from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.telnet_honeypot import TelnetHoneypot
from app.honeypots.smtp_honeypot import SMTPHoneypot
from app.honeypots.rdp_honeypot import RDPHoneypot

HONEYPOT_TYPES = {
    "FTP": FTPHoneypot,
    "HTTP": HTTPHoneypot,
    "SSH": SSHHoneypot,
    "TELNET": TelnetHoneypot,
    "SMTP": SMTPHoneypot,
    "RDP": RDPHoneypot,
}
