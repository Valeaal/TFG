# shared.py
import multiprocessing

# Variables globales que serán inicializadas por el proceso principal
manager = None
packetBuffer = None
packetBufferLock = None

def initialize_shared():
    """Inicializa las estructuras compartidas."""
    global manager, packetBuffer, packetBufferLock
    if manager is None:  # Solo inicializar si no se ha hecho ya
        manager = multiprocessing.Manager()
        packetBuffer = manager.list()
        packetBufferLock = multiprocessing.Lock()