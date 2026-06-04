# Capturas de pantalla — STP Claim Root Attack

Capturas del laboratorio en orden de demostración.

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | [01_topologia.png](01_topologia.png) | Vista general de la topología en PNETLab con nombre y matrícula visibles |
| 2 | [02_spanning_tree_antes_sw1.png](02_spanning_tree_antes_sw1.png) - [02_spanning_tree_antes_sw2.png](screenshots/02_spanning_tree_antes_sw2.png) | Salida de `show spanning-tree vlan 10` en SW1/SW2 **antes** del ataque — Root legítimo |
| 3 | [03_script_ejecutandose.png](03_script_ejecutandose.png) | Terminal de Kali Linux ejecutando el script STP Root Claim |
| 4 | [04_spanning_tree_durante.png](04_spanning_tree_durante.png) | SW2 reconociendo `0000.0000.0001` como nuevo Root Bridge |
| 5  | [05_ping_estable_durante_ataque.png](05_ping_estable_durante_ataque.png) | Tráfico ICMP continuo desde VPC1 sin pérdida de paquetes, demostrando una reconvergencia transparente y la naturaleza sigilosa del ataque. |
| 6 | [06_contramedida_aplicada.png](06_contramedida_aplicada.png) | Configuración de `spanning-tree bpduguard enable` en la interfaz del atacante |
| 7 | [07_puerto_err_disabled.png](07_puerto_err_disabled.png) | Puerto Et0/3 en estado `err-disabled` tras detectar el BPDU malicioso |
