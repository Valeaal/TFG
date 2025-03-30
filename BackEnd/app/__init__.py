import multiprocessing

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from .packetCapture import *
from .loadDefenseAlgorithms import *
from .attackNotify import AttackNotifier
from .bufferMonitor import bufferMonitor
from .bufferCleaner import bufferCleaner
from .loadAttackTests import loadAttackTests

from .routes.loadAttackTests import loadAttackTests_bp
from .routes.loadDefenseAlgorithms import loadDefenseAlgorithms_bp

app = Flask(__name__)
global attackNotifier
socketio = SocketIO(app, cors_allowed_origins="*")

CORS(app, resources={r"/*": {"origins": "*"}})

def createApp():

    app.register_blueprint(loadDefenseAlgorithms_bp, url_prefix="/loadDefenseAlgorithms")
    app.register_blueprint(loadAttackTests_bp, url_prefix="/loadAttackTests")

    # Creación del notificador de ataques al frontend, variable (objeto) global para todos los modulos
    global attackNotifier
    attackNotifier = AttackNotifier(socketio)

    # Hilo de captura de paquetes

    captureProcess = multiprocessing.Process(target=packetCapture, args=(socketio,), daemon=True)
    captureProcess.start()

    # Cargar algoritmos de defensa
    loadDefenseAlgorithms()

    # Cargar algoritmos de ataque
    loadAttackTests()

    # Envio constante del estado del buffer al frontend
    bufferMonitorProcess = multiprocessing.Process(target=bufferMonitor, args=(socketio,), daemon=True)
    bufferMonitorProcess.start()

    # Hilo de limpieza del buffer
    cleanerProcess = multiprocessing.Process(target=bufferCleaner, daemon=True)
    cleanerProcess.start()

    return app

