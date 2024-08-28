from flask import Flask, jsonify, send_file
from flask_cors import CORS
import json
import os
import subprocess
import io
from packet_analysis import load_packet_data, analyze_packet_data, analyze_tcp_flags

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains
# CORS(app, resources={r"/*": {"origins": "http://localhost:5000"}})

PACKET_DATA_FILE = 'packets.json'
ANALYSIS_DATA_FILE = 'analysis.json'
MAIN_PY_PROCESS = None
ANALYSIS_PROCESS = None

PACKET_DATA_FILE = 'packets.json'
ANALYSIS_DATA_FILE = 'analysis.json'
MAIN_PY_PROCESS = None
ANALYSIS_PROCESS = None

@app.route('/get-live-packets', methods=['GET'])
def get_live_packets():
    if os.path.exists(PACKET_DATA_FILE):
        with open(PACKET_DATA_FILE, 'r') as file:
            packets = [json.loads(line) for line in file]
        
        return jsonify({"status": "Success", "packets": packets})
    else:
        return jsonify({"status": "Failed", "error": "Packet data file not found"})

@app.route('/start-sniffing', methods=['POST'])
def start_sniffing():
    global MAIN_PY_PROCESS
    open(PACKET_DATA_FILE, 'w').close()  

    if not os.path.isfile('main.py'):
        return jsonify({"status": "Failed", "error": "main.py not found"})

    if MAIN_PY_PROCESS is None or MAIN_PY_PROCESS.poll() is not None:
        try:
            MAIN_PY_PROCESS = subprocess.Popen(['python', 'main.py'])
            return jsonify({"status": "Sniffing started"})
        except Exception as e:
            return jsonify({"status": "Failed", "error": str(e)})
    else:
        return jsonify({"status": "Already sniffing"})
    
@app.route('/stop-sniffing', methods=['POST'])
def stop_sniffing():
    global MAIN_PY_PROCESS

    if MAIN_PY_PROCESS and MAIN_PY_PROCESS.poll() is None:
        try:
            MAIN_PY_PROCESS.terminate()
            MAIN_PY_PROCESS.wait()
            return jsonify({"status": "Sniffing stopped"})
        except Exception as e:
            return jsonify({"status": "Failed", "error": str(e)})
    else:
        return jsonify({"status": "Not sniffing or already stopped"})

@app.route('/start-analysis', methods=['POST'])
def start_analysis():
    global ANALYSIS_PROCESS
    open(ANALYSIS_DATA_FILE, 'w').close()

    if not os.path.isfile('packet_analysis.py'):
        return jsonify({"status": "Failed", "error": "packet_analysis.py not found"})

    if ANALYSIS_PROCESS is None or ANALYSIS_PROCESS.poll() is not None:
        try:
            ANALYSIS_PROCESS = subprocess.Popen(['python', 'packet_analysis.py'])
            return jsonify({"status": "Analysis started"})
        except Exception as e:
            return jsonify({"status": "Failed", "error": str(e)})
    else:
        return jsonify({"status": "Already analyzing"})
    
@app.route('/get-analysis-data', methods=['GET'])
def get_analysis_data():
    if not os.path.exists(ANALYSIS_DATA_FILE):
        return jsonify({"status": "Failed", "error": "Analysis data file not found"})

    try:
        with open(ANALYSIS_DATA_FILE, 'r') as file:
            # Read the entire file content and parse it as a single JSON object
            analysis_data = json.load(file)
        return jsonify({"status": "Success", "analysis": analysis_data})
    except json.JSONDecodeError as e:
        return jsonify({"status": "Failed", "error": f"JSON decode error: {e}"})
    except IOError as e:
        return jsonify({"status": "Failed", "error": f"Error reading analysis data: {e}"})


if __name__ == '__main__':
    app.run(debug=True)





















