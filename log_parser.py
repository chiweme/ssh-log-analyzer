import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional 

@dataclass
class AuthEvent:
    timestamp: datetime
    host: str
    event_type: str
    user: Optional[str]
    ip: Optional[str]
    port: Optional[int]
    raw: str 
    


LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$" 
)


FAILED_INVALID_RE = re.compile(
    r"Failed password for invalid user (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


FAILED_VALID_RE = re.compile(
    r"Failed password for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


ACCEPTED_RE = re.compile(
    r"Accepted (?:publickey|password|keyboard-interactive/pam) "
    r"for (?P<user>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)


INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) "
    r"from (?P<ip>\S+) "
    r"port (?P<port>\d+)"
)


PATTERNS = [
    ("accepted", ACCEPTED_RE),
    ("failed_invalid", FAILED_INVALID_RE),
    ("failed_valid", FAILED_VALID_RE),
    ("invalid_user", INVALID_USER_RE),
]

def parse_line(line):
    #match the overall log line
    match = LINE_RE.match(line)
    
    if not match:
        return None
    
    #get the information captured by LINE_RE
    data = match.groupdict()
    
    #convert the syslog timestamp into a datetime object
    timestamp = datetime.strptime(
        f"{data['month']} {data['day']} {data['time']} {datetime.now().year}",
        "%b %d %H:%M:%S %Y"
    )
    
    #try each message pattern 
    for event_type, pattern in PATTERNS:
        msg_match = pattern.search(data["msg"])
        
        if msg_match:
            event_data = msg_match.groupdict()
            
            return AuthEvent(
                timestamp=timestamp,
                host=data["host"],
                event_type=event_type,
                user=event_data["user"],
                ip=event_data["ip"],
                port=int(event_data["port"]),
                raw=line,
            )
            

#the line was an ssh line, but we dont recognize its message 
    return None     

def parse_log_text(text: str) -> list[AuthEvent]:
    events = []
    for raw_line in text.splitlines():
        evt = parse_line(raw_line)
        if evt is not None:
            events.append(evt)
    return events 