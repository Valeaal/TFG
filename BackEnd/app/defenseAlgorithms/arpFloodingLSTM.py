import os
import time
import joblib
import warnings
import numpy as np
import pandas as pd
from app import attackNotifier
from scapy.layers.l2 import ARP
from scapy.layers.inet import TCP, UDP, ICMP
from shared import packetBuffer, packetBufferLock
from tensorflow.keras.models import load_model  # type: ignore

# Configuración
ALGORITHM_NAME = os.path.basename(__file__).replace('.py', '')
running = False  # Control de ejecución
warnings.simplefilter("ignore", category=UserWarning)

# Cargar modelo, scaler y el diccionario de encoders
model = load_model('./app/machineModels/models/arpFloodingLSTM.h5')
scaler = joblib.load('./app/machineModels/models/arpFloodingLSTM.pkl')
label_encoders = joblib.load('./app/machineModels/encoders/arpFloodingLSTM.pkl')

# Variables globales
prev_time = None
BATCH_SIZE = 200  # Tamaño del lote
current_batch = []  # Lista para acumular los paquetes en lotes
frame_number = 0  # Contador de número de trama dentro del batch

def extract_features(packet, prev_time, frame_number):
    """
    Extrae las características del paquete necesarias para la predicción.
    Se aseguran que los valores sean numéricos y se rellenan los faltantes con 0.
    """
    # Inicializamos las características con los mismos nombres y orden que en el entrenamiento.
    features = {
        "protocol": "OTHER",             # Se deja como string para luego transformarlo
        "frame.number": frame_number,    # Número de trama dentro del batch
        "frame.time_delta": 0.0,         # Delta de tiempo (float)
        "frame.len": 0,                  # Longitud del paquete (int)
        "arp.opcode": 0,                 # Opcode ARP
        "tcp.srcport": 0,                # Puerto origen TCP
        "tcp.dstport": 0,                # Puerto destino TCP
        "tcp.seq": 0,                    # Secuencia TCP
        "tcp.ack": 0,                    # Confirmación TCP
        "tcp.window_size": 0,            # Tamaño de ventana TCP
        "tcp.flags": 0,                  # Banderas TCP
        "ip.hdr_len": 0,                 # Longitud del encabezado IP
        "tcp.hdr_len": 0,                # Longitud del encabezado TCP
        "data.len": 0,                   # Longitud de los datos
        "icmp.type": 0,                  # Tipo ICMP
    }

    current_time_val = packet.time
    time_delta = current_time_val - prev_time if prev_time is not None else 0.0
    features["frame.time_delta"] = time_delta

    # Extraer información según el tipo de paquete
    if packet.haslayer(ARP):
        features["arp.opcode"] = packet[ARP].op
        features["protocol"] = "ARP"
    elif packet.haslayer(TCP):
        features["protocol"] = "TCP"
        features["tcp.srcport"] = packet[TCP].sport
        features["tcp.dstport"] = packet[TCP].dport
        features["tcp.seq"] = packet[TCP].seq
        features["tcp.ack"] = packet[TCP].ack
        features["tcp.window_size"] = packet[TCP].window
        features["tcp.flags"] = packet[TCP].flags
        features["tcp.hdr_len"] = packet[TCP].dataofs * 4  # En bytes
        features["data.len"] = len(packet[TCP].payload)
    elif packet.haslayer(UDP):
        features["protocol"] = "UDP"
        features["data.len"] = features["data.len"] = len(packet[UDP].payload)
    elif packet.haslayer(ICMP):
        features["protocol"] = "ICMP"
        features["icmp.type"] = packet[ICMP].type
        features["data.len"] = len(packet)

    features["frame.len"] = len(packet)

    # Para cualquier valor que sea string (excepto los que deben transformarse) o lista, asignar 0
    for key, value in features.items():
        if key not in label_encoders:  # Si no se codifica mediante encoder, forzamos numérico
            if isinstance(value, str) or isinstance(value, list):
                features[key] = 0

    # Ahora, transformar con el encoder correspondiente (por ejemplo, "protocol")
    for key, encoder in label_encoders.items():
        if key in features:
            try:
                features[key] = encoder.transform([features[key]])[0]
            except ValueError:
                # Si el valor no está en las clases conocidas, se asigna 0
                features[key] = 0

    # Orden de las características debe coincidir con el entrenamiento:
    feature_order = [
        "protocol", "frame.number", "frame.time_delta", "frame.len", "arp.opcode", 
        "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.window_size", 
        "tcp.flags", "ip.hdr_len", "tcp.hdr_len", "data.len", "icmp.type"
    ]

    df_features = pd.DataFrame([features])[feature_order]
    return df_features, current_time_val

def detect():
    global running, prev_time, current_batch, frame_number
    originalPackets = []

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
        packet = current_packet.packet

        if running:
            df_features, current_time_val = extract_features(packet, prev_time, frame_number)
            if df_features is not None:
                current_batch.append(df_features)
                originalPackets.append(packet)

                frame_number += 1

                if frame_number >= BATCH_SIZE:
                    batch_features = pd.concat(current_batch, ignore_index=True)
                    batch_features = batch_features.apply(lambda col: col.map(lambda x: float(x) if isinstance(x, (int, float)) else 0))
                    features_scaled = scaler.transform(batch_features)
                    features_scaled = features_scaled.reshape((1, BATCH_SIZE, features_scaled.shape[1]))
                    predictions = model.predict(features_scaled, verbose=0)

                    print(f"arpFlooding+ lote completado, forma de las predicciones: {predictions.shape}")

                    # Elimina la dimensión de batch, de (1, 100, 5) a (100, 5)
                    predictions = np.squeeze(predictions, axis=0)
                    for idx, prediction in enumerate(predictions):  
                        # Paquete original correspondiente
                        packet = originalPackets[idx]
                        # Probabilidades completas para todas las clases
                        probabilidad = prediction  # Esto ya contiene las probabilidades para las 5 clases

                        if packet.haslayer(ARP):  
                            arp_type = "reply" if packet[ARP].op == 2 else "request"
                            
                            # Imprimir las probabilidades de todas las clases
                            # print(f"Probabilidades por paquete (Clase 0-3): {probabilidad.tolist()}")  # Esto imprimirá las probabilidades de cada clase por paquete

                            # Seleccionar la mayor probabilidad
                            max_prob_class = np.argmax(probabilidad)  # Selecciona el índice de la clase con la mayor probabilidad

                            # Ahora comparamos con la clase 1 (que supongo corresponde a ARP)
                            if max_prob_class == 1:
                                print(f"🚨 ¡Alerta ARP Flooding! (ARP {arp_type} - Datos: {len(packet)} bytes - Probabilidad: {probabilidad[1]:.2%})")
                                attackNotifier.notifyAttack(ALGORITHM_NAME)
                            elif max_prob_class == 0:
                                print(f"✅ Tráfico normal (ARP {arp_type} - Datos: {len(packet)} bytes - Probabilidad: {probabilidad[0]:.2%})")

                    # Limpiar batch y lista de paquetes originales
                    current_batch = []
                    originalPackets = []
                    frame_number = 0

                prev_time = current_time_val

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
