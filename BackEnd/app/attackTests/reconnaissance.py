import time
import socket
from scapy.all import IP, TCP, sr1, RandShort

running = False  # Control de ejecución


def getLocalIp():
    """Obtiene la IP local de la máquina en la red"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        localIp = s.getsockname()[0]
        s.close()
        return localIp
    except Exception as e:
        print(f"Error al obtener IP local: {e}")
        return "127.0.0.1"  # Fallback


def synScan(targetIp, portRange=(1, 100)):
    """Escaneo SYN manual con Scapy"""
    for port in range(portRange[0], portRange[1] + 1):
        pkt = IP(dst=targetIp) / TCP(dport=port, flags='S', sport=RandShort())
        response = sr1(pkt, timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            print(f"⚠️ Puerto {port} probablemente abierto")


def attack():
    global running

    targetIp = getLocalIp()
    

    try:
        while True:

            while running:
                synScan(targetIp, portRange=(1, 100))
                time.sleep(0.01)

            time.sleep(1)
    except Exception as e:
        print(f"Error durante el ataque: {e}")

