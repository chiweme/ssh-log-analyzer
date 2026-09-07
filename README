# sshwatch

sshwatch is a Python-based SSH log analysis tool that parses authentication
logs and identifies suspicious login activity. It uses a two-tier
brute-force detection system — one detector looking for fast bursts of
failed attempts, and another identifying slower attacks spread over a
longer period. It also detects potential compromise scenarios, such as
multiple failed attempts followed by a successful login, and maps security
findings to MITRE ATT&CK techniques. Results are presented through a simple
web dashboard showing failed attempts, brute-force findings, low-and-slow
attacks, and compromise alerts.

## How to Run

1. Clone or download the project and open the project folder in VS Code.

2. Create a virtual environment:
```
python -m venv .venv
```

3. Activate the virtual environment (Windows PowerShell):
```
.venv\Scripts\Activate.ps1
```

4. Install the required dependencies:
```
pip install -r requirements.txt
```

5. Run the Flask application:
```
python app.py
```

6. Once the server starts, open the local address shown in the terminal (usually):
```
http://127.0.0.1:5000 
```

7. Upload an SSH authentication log through the dashboard and click Analyze to view the detected events and security findings.

## Running the tests

Tests are written as plain `assert`-based functions (no pytest dependency
required). Run the full suite with:

```
python run_tests.py
```

This runs all tests across `test_log_parser.py` and `test_analyzer.py` and
prints a pass/fail summary.