from flask import Flask, render_template, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Professional Database for Logic
VULN_DB = {
    "SQL Injection": {"sev": "Critical", "ref": "CWE-89", "desc": "Direct database query manipulation."},
    "Cross-Site Scripting (XSS)": {"sev": "High", "ref": "CWE-79", "desc": "Malicious script injection in browsers."},
    "IDOR": {"sev": "High", "ref": "CWE-639", "desc": "Unauthorized access to private objects."},
    "Broken Auth": {"sev": "Critical", "ref": "CWE-287", "desc": "Faulty session management or login logic."},
    "Rate Limiting": {"sev": "Low", "ref": "CWE-799", "desc": "Lack of request throttling on sensitive endpoints."}
}

@app.route('/')
def index():
    return render_template('index.html', vulns=VULN_DB)

@app.route('/generate', methods=['POST'])
def generate():
    data = request.form
    report_data = {
        "title": f"[{data.get('severity')}] {data.get('vultype')} @ {data.get('target')}",
        "date": datetime.now().strftime("%d %b %Y"),
        "vultype": data.get('vultype'),
        "target": data.get('target'),
        "endpoint": data.get('endpoint'),
        "severity": data.get('severity'),
        "steps": data.get('steps'),
        "payload": data.get('payload'),
        "impact": data.get('impact'),
        "ref": VULN_DB.get(data.get('vultype'), {}).get('ref', 'N/A')
    }
    return render_template('result.html', report=report_data)

if __name__ == '__main__':
    app.run(debug=True)