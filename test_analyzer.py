from datetime import datetime, timedelta 

from log_parser import parse_log_text 
from analyzer import count_failed_by_ip, detect_brute_force
from analyzer import find_compromise_alerts 
from analyzer import detect_low_and_slow_attacks


def test_count_failed_by_ip():
    with open("sample_data/mini_test.log") as f:
        events = parse_log_text(f.read())
    counts = count_failed_by_ip(events)
    assert counts == {"203.0.113.5": 2}
    
    
def test_brute_force_detects_fast_burst():
    with open("sample_data/brute_force_test.log") as f:
        events = parse_log_text(f.read())
    result = detect_brute_force(events)
    assert "198.51.100.9" in result
    assert result["198.51.100.9"]["count"] == 5
    assert result["198.51.100.9"]["mitre_technique"] == "T1110"
    
    
def test_brute_force_ignores_slow_attempts():
    with open("sample_data/slow_attack_test.log") as f:
        events = parse_log_text(f.read())
    result = detect_brute_force(events)
    assert result == {}
        

def test_compromise_alert_triggers_on_failures_then_success():
    with open("sample_data/compromise_test.log") as f:
        events = parse_log_text(f.read())
    alerts = find_compromise_alerts(events)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "198.51.100.50"
    assert alerts[0]["user"] == "admin"
    assert alerts[0]["failure_count"] == 3
    
    
def test_compromise_alert_ignores_single_typo():
    with open("sample_data/compromise_test.log") as f:
        events = parse_log_text(f.read())
    alerts = find_compromise_alerts(events)
    #persons single failed attempt + quick success should NOT add a second alert
    assert not any(a["ip"] == "10.0.0.9" for a in alerts)
    
    
def test_low_and_slow_detects_spread_out_attempts():
    with open("sample_data/low_and_slow_test.log") as f:
        events = parse_log_text(f.read())
    result = detect_low_and_slow_attacks(events)
    assert "198.51.100.50" in result
    assert result["198.51.100.50"]["mitre_technique"] == "T1110.001"
    
    
def test_low_and_slow_does_not_trigger_fast_detector():
    with open("sample_data/low_and_slow_test.log") as f:
        events = parse_log_text(f.read())
    result = detect_brute_force(events)
    assert result == {}