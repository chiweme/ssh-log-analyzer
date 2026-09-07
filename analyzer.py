from collections import defaultdict
from log_parser import AuthEvent

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60
COMPROMISE_MIN_FAILURES = 3
COMPROMISE_LOOKAHEAD_SECONDS = 120
LOW_AND_SLOW_THRESHOLD = 15
LOW_AND_SLOW_WINDOW_SECONDS = 24 * 60 * 60


def count_failed_by_ip(events: list[AuthEvent]) -> dict[str, int]:
    failed_counts = defaultdict(int)
    
    for event in events:
        if event.event_type in ("failed_invalid", "failed_valid"):
            failed_counts[event.ip] += 1
            
    return dict(failed_counts)

def _detect_attempts_in_window(events, threshold, window_seconds, technique_id, technique_name):
    failed_by_ip = defaultdict(list)
    for event in events:
        if event.event_type in ("failed_invalid", "failed_valid"):
            failed_by_ip[event.ip].append(event)
            
    flagged_ips = {}
    for ip, ip_events in failed_by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        window = []
        
        for event in ip_events:
            window.append(event)
            while (event.timestamp - window[0].timestamp).total_seconds() > window_seconds:
                window.pop(0)
            if len(window) >= threshold:
                flagged_ips[ip] = {
                    "count": len(window),
                    "mitre_technique": technique_id,
                    "mitre_name": technique_name,
                }
                
    return flagged_ips


def detect_brute_force(events):
    return _detect_attempts_in_window(
        events, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS, 
        "T1110", "Brute Force"
    )
    
    
def detect_low_and_slow_attacks(events):
    return _detect_attempts_in_window(
        events, LOW_AND_SLOW_THRESHOLD, LOW_AND_SLOW_WINDOW_SECONDS,
        "T1110.001", "Brute Force: Password Guessing"
    )



def find_compromise_alerts(events: list[AuthEvent]) -> list[dict]:
    failed_types = ("failed_invalid", "failed_valid")
    
    by_ip = defaultdict(list)
    
    for e in events:
        if e.ip:
            by_ip[e.ip].append(e)
            
    alerts = []
    
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        failed_streak = []
        
        for e in ip_events:
            if e.event_type in failed_types:
                failed_streak.append(e)
                
            elif e.event_type == "accepted" and len(failed_streak) >= COMPROMISE_MIN_FAILURES:
                gap = (e.timestamp - failed_streak[-1].timestamp).total_seconds()
                
                if gap <= COMPROMISE_LOOKAHEAD_SECONDS:
                    alerts.append({
                        "ip": ip,
                        "user": e.user,
                        "failure_count": len(failed_streak),
                        "accepted_at": e.timestamp,
                        "mitre_technique": "T1078",
                        "mitre_name": "Valid Accounts",
                    })
                    
            if e.event_type == "accepted":
                    failed_streak = []
                    
    return alerts
