from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import gzip
import shutil
import subprocess
import json
import subprocess

app = Flask(__name__)
CORS(app)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    try:
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, file.filename)
        file.save(file_path)
        
        process_path = file_path
        
        # 1. Seamlessly decompress .gz files on the fly
        if file.filename.endswith('.gz'):
            process_path = os.path.join(temp_dir, "uncompressed.log")
            with gzip.open(file_path, 'rb') as f_in:
                with open(process_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
        # 2. Run the actual Python Validation Harness on the file!
        print(f"[*] Analyzing uploaded file: {file.filename} (Format agnostic)")
        cmd = ['python', 'validation/test_harness.py', '--zeek-log', process_path]
        
        result = subprocess.run(cmd, cwd=os.getcwd(), capture_output=True, text=True)
        
        report_file = "validation_report.json"
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                report_data = f.read()
            return report_data, 200, {'Content-Type': 'application/json'}
        else:
            return jsonify({'error': 'Test harness failed to generate report', 'logs': result.stdout + result.stderr}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/mark_intel', methods=['POST'])
def mark_intel():
    # Support both JSON and FormData
    ip = request.form.get('ip') if request.form else request.json.get('ip')
    classification = request.form.get('classification') if request.form else request.json.get('classification')
    
    intel_file = 'threat_intel.json'
    intel_data = {}
    if os.path.exists(intel_file):
        try:
            with open(intel_file, 'r') as f:
                intel_data = json.load(f)
        except Exception:
            pass
            
    intel_data[ip] = classification
    with open(intel_file, 'w') as f:
        json.dump(intel_data, f, indent=2)
        
    return jsonify({'success': True, 'message': f'IP {ip} added to Threat Intel Database as {classification}'})

if __name__ == '__main__':
    print("[*] Starting OmniLog Validation API Server on port 5000...")
    app.run(port=5000, debug=False)
