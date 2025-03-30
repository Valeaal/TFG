import os
import time
import joblib
import warnings
import numpy as np
from app import attackNotifier
from scapy.all import IP, TCP, IPv6
from shared import packetBuffer, packetBufferLock
from tensorflow.keras.models import load_model  # type: ignore

ALGORITHM_NAME = os.path.basename(__file__).replace('.py', '')
running = False  # Variable global para detener el algoritmo

warnings.simplefilter("ignore", category=UserWarning)

# Cargar modelo y escalador
model = load_model('./app/machineModels/models/tcpSYN.h5')
scaler = joblib.load('./app/machineModels/models/tcpSYN.pkl')

# Diccionario global para mantener estadísticas por flujo (clave = src_tuple o reverse_tuple)
# Se guarda: packet_count (por flujo)
flow_stats = {}

# Variable global para almacenar el tiempo del último paquete (global, no por flujo)
last_packet_time = None

def extract_features(packet):
    """
    Extrae las características de un paquete TCP:
    - Time Delta: Diferencia de tiempo respecto al último paquete (global).
    - Flags TCP: SYN, URG, ACK, PSH, FIN, RST.
    - packetCountInFlow: Número de paquetes en el flujo.
    """
    if IP not in packet or TCP not in packet:
        return None

    # Identificar el flujo
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    src_tuple = (src_ip, dst_ip, src_port, dst_port)
    reverse_tuple = (dst_ip, src_ip, dst_port, src_port)

    # Determinar qué clave usar (src_tuple o reverse_tuple)
    if src_tuple in flow_stats:
        stats = flow_stats[src_tuple]
    elif reverse_tuple in flow_stats:
        stats = flow_stats[reverse_tuple]
    else:
        # Crear un nuevo flujo con src_tuple como clave
        stats = {'packet_count': 0}
        flow_stats[src_tuple] = stats

    # Calcular el delta de tiempo con el tiempo del último paquete global
    global last_packet_time
    current_time = packet.time
    if last_packet_time is None:
        time_delta = 0.0
    else:
        time_delta = current_time - last_packet_time
    last_packet_time = current_time

    # Incrementar el conteo de paquetes en el flujo
    stats['packet_count'] += 1

    # Extraer banderas TCP
    tcp_flags = packet[TCP].flags
    flags = {
        'SYN': 1 if 'S' in tcp_flags else 0,
        'URG': 1 if 'U' in tcp_flags else 0,
        'ACK': 1 if 'A' in tcp_flags else 0,
        'PSH': 1 if 'P' in tcp_flags else 0,
        'FIN': 1 if 'F' in tcp_flags else 0,
        'RST': 1 if 'R' in tcp_flags else 0
    }

    # Vector de características: [Time Delta, FlagSYN, FlagURG, FlagACK, FlagPSH, FlagFIN, FlagRST, packetCountInFlow]
    features = np.array([[time_delta, *flags.values(), stats['packet_count']]])
    return features

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

    # Nombres de las características para mostrar en el log
    feature_names = ['Time Delta', 'FlagSYN', 'FlagURG', 'FlagACK', 'FlagPSH', 'FlagFIN', 'FlagRST', 'packetCountInFlow']

    while True:
        packet = current_packet.packet  # Paquete actual

        if running and IP in packet and TCP in packet:
            features = extract_features(packet)

            if features is not None:
                # Escalar las características (todas se usan en la predicción)
                features_scaled = scaler.transform(features)
                # Realizar la predicción
                prediction = model.predict(features_scaled, verbose=0)
                prob_attack = prediction[0][0]

                print(f"----------------- {ALGORITHM_NAME} -----------------")
                if prob_attack > 0.5:
                    print(f"🚨 ¡Alerta TCP SYN Flooding! (Prob attk: {prob_attack:.2%})")
                    attackNotifier.notifyAttack(ALGORITHM_NAME)
                else:
                    print(f"✅ Tráfico normal (Prob attk: {prob_attack:.2%})")

                for name, value in zip(feature_names, features[0]):
                    print(f"{name}: {value}")
                print(f"Source IP: {packet[IP].src}")
                print(f"Destination IP: {packet[IP].dst}")

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
