import requests
from flask import Flask, render_template, request, jsonify
import os
import subprocess
import threading

app = Flask(__name__)

RYU_CONTROLLER_IP = '127.0.0.1'
RYU_CONTROLLER_PORT = 8080
SCRIPT_FOLDER = 'skrypty'

# referencje do uruchomionych procesów
running_processes = {}
process_outputs = {}

# folder na skrypty
os.makedirs(SCRIPT_FOLDER, exist_ok=True)

# Lock do dostępu do wyjść procesów
output_lock = threading.Lock()

def get_topology_data():
    url = f'http://{RYU_CONTROLLER_IP}:{RYU_CONTROLLER_PORT}/v1/topology'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_statistics_data():
    url = f'http://{RYU_CONTROLLER_IP}:{RYU_CONTROLLER_PORT}/v1/stats'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

@app.route('/')
def index():
    topology_data = get_topology_data()
    statistics_data = get_statistics_data()
    skrypty = [f for f in os.listdir(SCRIPT_FOLDER) if f.endswith('.py')]
    if topology_data and statistics_data:
        return render_template('index.html', topology_data=topology_data, statistics_data=statistics_data, skrypty=skrypty)
    else:
        return "Nie można pobrać danych topologii lub statystyk"
             


@app.route('/statistics_data')
def statistics_data_route():
    statistics_data = get_statistics_data()
    if statistics_data:
        return jsonify(statistics_data)
    else:
        return jsonify({'error': 'Nie można pobrać danych statystyk'})

def read_process_output(process, script_name):
    """Funkcja do ciągłego odczytywania danych wyjściowych procesu Ryu"""
    with output_lock:
        process_outputs[script_name] = ""
    for line in process.stdout:
        with output_lock:
            process_outputs[script_name] += line

@app.route('/run-script', methods=['POST'])
def run_script():
    script_name = request.json.get('script_name')
    if script_name:
        if script_name in running_processes:
            return jsonify({'output': '', 'error': 'Skrypt już działa'})

        try:
            # Uruchomienie skryptów
            process = subprocess.Popen(
                ['ryu-manager', os.path.join(SCRIPT_FOLDER, script_name)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            running_processes[script_name] = process
            process_outputs[script_name] = ""

            threading.Thread(target=read_process_output, args=(process, script_name), daemon=True).start()
            
            return jsonify({'output': f'Skrypt Ryu {script_name} uruchomiony', 'error': None})
        except Exception as e:
            return jsonify({'output': '', 'error': str(e)})
    else:
        return jsonify({'output': '', 'error': 'Nie wybrano skryptu'})

@app.route('/script-output/<script_name>', methods=['GET'])
def script_output(script_name):
    if script_name in running_processes:
        process = running_processes[script_name]
        if process.poll() is None:  # Proces nadal działa
            with output_lock:
                output = process_outputs.get(script_name, "")
            return jsonify({'output': output, 'running': True})
        else:
            # Proces zakończony
            with output_lock:
                output = process_outputs.pop(script_name, "")
            running_processes.pop(script_name)
            return jsonify({'output': output, 'running': False})
    else:
        return jsonify({'output': '', 'error': 'Skrypt nie jest uruchomiony'})

@app.route('/stop-script', methods=['POST'])
def stop_script():
    script_name = request.json.get('script_name')
    if script_name and script_name in running_processes:
        process = running_processes.pop(script_name)
        process.terminate()  # Próbuj zakończyć proces
        process.wait()  # Czekaj na zakończenie
        with output_lock:
            output = process_outputs.pop(script_name, "")
        return jsonify({'output': f'Skrypt Ryu {script_name} zatrzymany', 'error': None})
    else:
        return jsonify({'output': '', 'error': 'Skrypt nie jest uruchomiony lub nie istnieje'})


@app.route('/upload-script', methods=['POST'])
def upload_script():
    if 'file' not in request.files:
        return jsonify({'error': 'Brak pliku w żądaniu'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'Nie wybrano pliku'})
    
    if not file.filename.endswith('.py'):
        return jsonify({'error': 'Plik musi mieć rozszerzenie .py'})
    
    file_path = os.path.join(SCRIPT_FOLDER, file.filename)
    file.save(file_path)
    
    return jsonify({'message': f'Skrypt {file.filename} został pomyślnie przesłany'})

    
if __name__ == '__main__':
    app.run(host='0.0.0.0')
    app.run(debug=True)