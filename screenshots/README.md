# Capturas de pantalla — STP Claim Root Attack

Capturas del laboratorio en orden de demostración.

| Archivo | Descripción |
|---------|-------------|
| `01_topologia.png` | Topología en PNETLab con nombre y matrícula visibles |
| `02_spanning_tree_antes.png` | Salida de `show spanning-tree vlan 1` — Root Bridge legítimo antes del ataque |
| `03_script_ejecutandose.png` | Terminal Kali corriendo el script STP Root Claim |
| `04_spanning_tree_durante.png` | SW2 mostrando `0000.0000.0001` como nuevo Root Bridge |
| `05_ping_cayendo.png` | Paquetes ICMP fallando desde VPC1 durante la reconvergencia (DoS) |
| `06_contramedida_aplicada.png` | Configuración `spanning-tree bpduguard enable` en la interfaz del atacante |
| `07_puerto_err_disabled.png` | Puerto Et0/3 en estado `err-disabled` tras detectar el BPDU malicioso |
