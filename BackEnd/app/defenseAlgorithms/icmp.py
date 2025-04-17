import os
import time
import joblib
import warnings
import numpy as np
from app import attackNotifier
from scapy.all import IP, TCP, IPv6, ICMP
from app.packetCapture import packetBuffer, packetBufferLock
from tensorflow.keras.models import load_model  # type: ignore

ALGORITHM_NAME = os.path.basename(__file__).replace('.py', '')
running = False  # Variable global para detener el algoritmo

warnings.simplefilter("ignore", category=UserWarning)


def detect():
    global running

###### OBTENCIÓN DEL PRIMER PAQUETE ######
    with packetBufferLock:
        while len(packetBuffer) == 0:
            time.sleep(0.5)
        current_packet = packetBuffer[0]

    while True:
        packet = current_packet.packet  # Paquete actual

###### PROCESO DE ANALISIS ######

        if running:
            if packet.haslayer(ICMP):
                ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
                print(f"[ICMP detectado] Origen: {ip_layer.src} → Destino: {ip_layer.dst}")

###### PROCESO DE ENLACE AL SIGUIENTE PAQUETE ######

        with packetBufferLock:
            current_index = packetBuffer.index(current_packet)
            remaining_packets = len(packetBuffer) - (current_index + 1)

        while remaining_packets == 0:
            time.sleep(0.5)
            with packetBufferLock:
                current_index = packetBuffer.index(current_packet)
                remaining_packets = len(packetBuffer) - (current_index + 1)

        with packetBufferLock:
            current_index = packetBuffer.index(current_packet)
            remaining_packets = len(packetBuffer) - (current_index + 1)
            next_packet = packetBuffer[current_index + 1]

###### PROCESO DE MARCADO COMO ANALIZADO ######

        current_packet.mark_processed(ALGORITHM_NAME)
        current_packet = next_packet
