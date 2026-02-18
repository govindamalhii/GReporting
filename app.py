from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

# Predefined professional data
VULN_DB = {
    "SQL Injection": {"sev": "Critical", "desc": "Allows unauthorized database manipulation.", "rec": "Use parameterized queries and input validation."},
    "Cross-Site Scripting (XSS)": {"sev": "High", "desc": "Allows execution of malicious scripts in the victim's browser.", "rec": "Implement CSP and output encoding."},
    "IDOR": {"sev": "High", "desc": "Direct access to objects without authorization.", "rec": "Implement strict object-level access controls."},
    "Open Redirect": {"sev": "Medium", "desc": "Redirects users to malicious external sites.", "rec": "Use a whitelist for all redirect URLs."}
}

@app.route('/')
def index():
    return render_template('index.html', vulns=VULN_DB)

@app.route('/generate', methods=['POST'])
def generate():
    data = request.form
    report_data = {
        "title": f"[{data.get('severity')}] {data.get('vultype')} on {data.get('target')}",
        "date": datetime.now().strftime("%d %b %Y"),
        "vultype": data.get('vultype'),
        "target": data.get('target'),
        "endpoint": data.get('endpoint'),
        "severity": data.get('severity'),
        "steps": data.get('steps'),
        "payload": data.get('payload'),
        "impact": data.get('impact'),
        "description": VULN_DB.get(data.get('vultype'), {}).get('desc', 'N/A'),
        "recommendation": VULN_DB.get(data.get('vultype'), {}).get('rec', 'N/A')
    }
    return render_template('result.html', report=report_data)

if __name__ == '__main__':
    app.run(debug=True)