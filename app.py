from flask import Flask, jsonify, request, render_template

from log_parser import parse_log_text
from analyzer import count_failed_by_ip, detect_brute_force, find_compromise_alerts, detect_low_and_slow_attacks

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("dashboard.html")

@app.route("/api/demo")
def api_demo():
    with open("sample_data/compromise_test.log") as f:
        text = f.read()
    events = parse_log_text(text)
    result = {
        "total_events": len(events),
        "failed_by_ip": count_failed_by_ip(events),
        "brute_force": detect_brute_force(events),
        "compromise": find_compromise_alerts(events),
    }
    return jsonify(result)
    
    
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded. EXpected a field named 'logfile'."}), 400
    
    file = request.files["logfile"]
    text = file.read().decode("utf-8", errors="replace")
    
    events = parse_log_text(text)
    
    result = {
        "total_events": len(events),
        "failed_by_ip": count_failed_by_ip(events),
        "brute_force": detect_brute_force(events),
        "low_and_slow": detect_low_and_slow_attacks(events),
        "compromises": find_compromise_alerts(events),
    }
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)