import time
from .shared import packetBuffer, packetBufferLock

def bufferMonitor(socketio):
    print(f"Emitiendo estado del buffer")
    while True:
        time.sleep(0.2)
        socketio.emit('buffer_status', {'size': len(packetBuffer)})
        #print(f"Emitiendo desde el socket: {len(packetBuffer)}")
