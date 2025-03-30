import multiprocessing
from scapy.all import sniff, Packet, IP
from .shared import packetBuffer, packetBufferLock
from .loadDefenseAlgorithms import getDefenseAlgorithmNames

defenseAlgorithmsNames = getDefenseAlgorithmNames()

def packetCapture(socketio):
    # print(f"defenseAlgorithmsNames: ", defenseAlgorithmsNames)
    
    def process_packet(packet):
        indexedPacket = PacketIndexed(packet, defenseAlgorithmsNames)
        with packetBufferLock:
            packetBuffer.append(indexedPacket)
        # print("Paquete tipo " + str(indexedPacket.get_last_layer()) + " IP origen: " + (indexedPacket.packet[IP].src if indexedPacket.packet.haslayer(IP) else "No IP"))       
        socketio.emit('packet_layer_info', {'last_layer': indexedPacket.get_last_layer()})

    sniff(prn=process_packet, store=False)

# Estructura de datos que almacena un paquete junto con los filtros que ya ha pasado o no
class PacketIndexed:
    def __init__(self, packet, defenseAlgorithms):
        self.packet = packet
        self.processed = {name: 0 for name in defenseAlgorithms}
        self.lock = multiprocessing.Lock()

    def mark_processed(self, filter_name):
        # Marca el filtro como procesado para este paquete
        with self.lock:
            self.processed[filter_name] = 1
        
    def is_processed_by_algorithm(self, filter_name):
        # Verifica si el paquete ha sido procesado por un filtro específico
        with self.lock:
            return self.processed.get(filter_name, 0) == 1  # Retorna True si está procesado, False si no lo está

    def get_last_layer(self):
        excluded_layers = {'Raw', 'Padding'}
        if isinstance(self.packet, Packet):
            # Itera las capas en orden inverso (de más alta a más baja)
            for layer in reversed(self.packet.layers()):
                layer_name = layer.__name__
                if layer_name not in excluded_layers:
                    return layer_name
        return "Desconocido"

