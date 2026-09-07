from log_parser import parse_line

def test_parse_failed_invalid_user():
    line = "Mar 3 03:14:15 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed_invalid"
    assert event.user == "admin"
    assert event.ip == "203.0.113.5"
    assert event.port == 51515
    

def test_parse_accepted_login():
    line = "Mar 3 03:15:00 web01 sshd[1235]: Accepted publickey for deploy from 10.0.0.5 port 44000 ssh2"
    event = parse_line(line)
    assert event is not None 
    assert event.event_type == "accepted"
    assert event.user == "deploy"
    assert event.ip == "10.0.0.5"
    assert event.port == 44000