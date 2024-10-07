from scapy.all import sniff

def mostrar_paquete(paquete):
    print(paquete.summary())

# Reemplaza 'Wi-Fi' con el nombre exacto de tu interfaz
sniff(iface='Wi-Fi', prn=mostrar_paquete, store=False)
