import subprocess
import os
import signal

# Ścieżka do katalogu 'ryu/'
ryu_dir = os.path.join(os.getcwd(), 'ryu')

# Polecenie do wykonania w katalogu 'ryu/'
cmd1 = ['ryu-manager', '--observe-links', 'controler.py', 'monitoringdelay.py']

# Uruchomienie pierwszego polecenia w tle
p1 = subprocess.Popen(cmd1, cwd=ryu_dir)

# Polecenie do wykonania w bieżącym katalogu
cmd2 = ['python3', 'app.py']

# Uruchomienie drugiego polecenia w tle
p2 = subprocess.Popen(cmd2)


print("\n=================================================================\n")
print("Aplikacja została uruchomiona. Aby ją zatrzymać, naciśnij Ctrl+C.")
print("\n=================================================================")

try:
    # Czekanie na zakończenie procesów
    p1.wait()
    p2.wait()
except KeyboardInterrupt:
    print("\n=============================")
    print("\nZatrzymywanie aplikacji...")
    # Zakończenie procesów
    p1.terminate()
    p2.terminate()
    p1.wait()
    p2.wait()
    print("Aplikacja została zatrzymana.")
    print("\n=============================")