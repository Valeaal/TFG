import os
import time
import joblib
import warnings
import numpy as np

from app import attackNotifier
from scapy.layers.l2 import ARP, Ether
from shared import packetBuffer, packetBufferLock
from tensorflow.keras.models import load_model  # type: ignore


ALGORITHM_NAME = os.path.basename(__file__).replace('.py', '')
running = False # Variable global de control para detener el algoritmo

warnings.simplefilter("ignore", category=UserWarning)

# Cargar modelo entrenado y escalador
model = load_model('./app/machineModels/models/arpFlooding.h5')
scaler = joblib.load('./app/machineModels/models/arpFlooding.pkl')

# Diccionarios globales para métricas en tiempo real
arp_counts = {}  
arp_request_counts = {}  
arp_reply_counts = {}  
unique_dst_ips = {}  # Para IPs destino únicas

def mac_to_int(mac):
    return int(mac.replace(":", ""), 16) if isinstance(mac, str) else 0

def extract_features(packet):
    if packet.haslayer(ARP) and packet.haslayer(Ether):
        arp_layer = packet[ARP]
        ether_layer = packet[Ether]

        src_mac_arp = mac_to_int(arp_layer.hwsrc)
        src_mac_eth = mac_to_int(ether_layer.src)
        op_code = arp_layer.op  # 1 = Request, 2 = Reply
        dst_ip = arp_layer.pdst if op_code == 1 else "0.0.0.0"  # Obtener IP destino

        # Inicializar contadores si la MAC no existe
        if src_mac_arp not in arp_counts:
            arp_counts[src_mac_arp] = 0
            arp_request_counts[src_mac_arp] = 0
            arp_reply_counts[src_mac_arp] = 0
            unique_dst_ips[src_mac_arp] = set()

        # Actualizar conteo de paquetes ARP
        arp_counts[src_mac_arp] += 1

        # Actualizar conteo de requests y conjunto de IPs únicas
        if op_code == 1:
            arp_request_counts[src_mac_arp] += 1
            if dst_ip not in ["0.0.0.0", "", None] and arp_layer.ptype == 0x0800:  # IPv4
                unique_dst_ips[src_mac_arp].add(dst_ip)
        elif op_code == 2:
            arp_reply_counts[src_mac_arp] += 1

        # Calcular métricas
        ratio_request_reply = arp_request_counts[src_mac_arp] / (arp_reply_counts[src_mac_arp] + 1e-6)
        unique_ip_count = len(unique_dst_ips[src_mac_arp])

        features = np.array([
            op_code,                           # op_code(arp)
            int(src_mac_eth != src_mac_arp),   # mac_diferente_eth_arp
            arp_counts[src_mac_arp],           # arp_packets_por_mac
            arp_request_counts[src_mac_arp],   # arp_request_count
            arp_reply_counts[src_mac_arp],     # arp_reply_count
            ratio_request_reply,               # ratio_request_reply
            unique_ip_count                    # unique_dst_ip_count
        ]).reshape(1, -1)

        return features
    else:
        return None
    
def detect():

    global running

    current_packet = None
    while current_packet == None:
        try:
            with packetBufferLock:
                if len(packetBuffer) > 0:
                    current_packet = packetBuffer[0]
                else:
                    current_packet = None
                    time.sleep(0.5)
        except:
            current_packet == None
            
    while True:
        packet = current_packet.packet  # Referencia al paquete actual

        ### PROCESO DE ANALISIS ###
        if running and packet.haslayer(ARP):
            features = extract_features(packet)
            print(f"-----------------arpFloodingBase-----------------------")
            # print("Características calculadas:", features[0])

            if packet.haslayer(ARP) and packet[ARP].op == 1:
                print(f"ARP Request: Busca la IP {packet[ARP].pdst}")
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                print(f"ARP Reply: La IP {packet[ARP].psrc} es {packet[ARP].hwsrc}")

            # Escalar características y hacer la predicción
            features_scaled = scaler.transform(features)
            prediction = model.predict(features_scaled, verbose=0)

            # Umbral de detección
            if prediction[0] > 0.5:
                print(f"🚨 ¡Alerta ARP Flooding! (Prob attk: {prediction[0][0]:.2%})")
                attackNotifier.notifyAttack(ALGORITHM_NAME)
            else:
                print(f"✅ Tráfico normal (Prob attk: {prediction[0][0]:.2%})")

        ### PROCESO DE ENLACE AL SIGUIENTE PAQUETE ###

        # Asignacion normal del siguiente indice:
        # Actualizamos siempre el indice del paquete actual, por si el cleaner ha limpiado el buffer y cambiado los mismos.
        with packetBufferLock:
            current_index = packetBuffer.index(current_packet)
            remaining_packets = len(packetBuffer) - (current_index + 1)
        
        # Si hemos acabado con el buffer:
        # El ultimo paquete no se marca como analizado para no perder la referencia del indice.
        # Cuando el limpiador actualice el buffer, el indice cambiara. 
        # Como tenemos aun tendremos un elemento, podemos usarlo para hallar el nuevo indice y a partir de ahi seguir.
        while remaining_packets == 0:
            time.sleep(0.5)                
            with packetBufferLock:
                current_index = packetBuffer.index(current_packet)
                remaining_packets = len(packetBuffer) - (current_index + 1)
        
        next_packet = packetBuffer[current_index + 1]

        #Cuando ya se ha actualizado el indice de forma segura con el siguiente paquete a analizar
        current_packet.mark_processed(ALGORITHM_NAME)
        current_packet = next_packet
                
