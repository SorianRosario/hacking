from scapy.all import sniff
import socket

# Función que se ejecuta cada vez que se captura un paquete
def mostrar_paquete(paquete):
    if paquete.haslayer("IP"):
        ip_origen = paquete['IP'].src
        ip_destino = paquete['IP'].dst
        
        # Intentar obtener el nombre del equipo de origen
        try:
            nombre_origen = socket.gethostbyaddr(ip_origen)[0]
        except socket.herror:
            nombre_origen = "No disponible"

        # Intentar obtener el nombre del servidor de destino
        try:
            nombre_destino = socket.gethostbyaddr(ip_destino)[0]
        except socket.herror:
            nombre_destino = "No disponible"
        
        print(f"IP origen: {ip_origen} ({nombre_origen}) -> Servidor destino: {ip_destino} ({nombre_destino})")

    elif paquete.haslayer("Ether"):
        print(f"MAC origen: {paquete['Ether'].src} -> MAC destino: {paquete['Ether'].dst}")

# Monitorear la interfaz de red (ej. 'eth0' para Linux, 'Wi-Fi' o 'Ethernet' para Windows)
def iniciar_monitoreo(interface='eth0'):
    print(f"Iniciando monitor de red en la interfaz {interface}...")
    sniff(iface=interface, prn=mostrar_paquete, store=False)

# Ejecución
if __name__ == "__main__":
    interfaz = input("Ingrese el nombre de la interfaz de red (ej. 'eth0', 'Wi-Fi', 'Ethernet'): ")
    iniciar_monitoreo(interfaz)
