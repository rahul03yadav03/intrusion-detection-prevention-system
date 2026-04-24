from flask import Flask, render_template_string
from config import log_file

app = Flask(__name__)

HTML = """
<!DOCTYPE html>          
<html>
<head>
    <title>IDPS Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #00ff00; }
        h1 { color: #ff4444; }
        pre { background: #000; padding: 20px; border-radius: 5px; overflow-x: auto; }
    </style>
    <meta http-equiv="refresh" content="10">
</head>
<body>
    <h1>🔒 IDPS Dashboard</h1>
    <h3>Blocked IP Logs:</h3>
    <pre>{{ logs }}</pre>
    <p><small>Auto-refreshes every 10 seconds</small></p>
</body>
</html>
"""

@app.route("/")
def home():
    try:
        with open(log_file, "r") as f:
            logs = f.read()
            if not logs.strip():
                logs = "No attacks detected yet."
    except FileNotFoundError:
        logs = "No logs yet. Start the IDPS first."
    except Exception as e:
        logs = f"Error reading logs: {e}"
    
    return render_template_string(HTML, logs=logs)

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)