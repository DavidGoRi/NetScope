# NetScope

*Read in [English](README.md).*

**Encuentra todos los dispositivos de tu red local, identifícalos y detecta los que suponen un riesgo, en unos diez segundos y sin permisos de administrador.**

NetScope recorre una red privada, deduce qué es cada dispositivo (router, impresora, cámara, NAS, PC con Windows, móvil…), comprueba una lista corta de puertos conocidos y genera un panel HTML de un solo archivo que señala lo que merece atención: una cámara con Telnet abierto, una impresora cuyo panel web no usa HTTPS, un Escritorio remoto accesible desde toda la red o **un dispositivo que ayer no estaba**.

### ▶ [Abrir la demo](https://davidgori.github.io/NetScope/?lang=es)

La demo muestra la red ficticia de una oficina con 20 dispositivos.

## Por qué

"¿Qué hay realmente conectado a nuestra red?" es una de las primeras preguntas en cualquier puesto de soporte o seguridad, y la respuesta suele ser una hoja de cálculo que nadie actualiza.

- **Sin dependencias:** solo la biblioteca estándar de Python. Ni Npcap, ni nmap, ni agentes.
- **Sin permisos de administrador:** usa el `ping` del sistema y la tabla ARP; los puertos se comprueban con conexiones TCP normales.
- **Seguro por diseño:** rechaza rangos públicos y redes de más de 1024 equipos, y solo comprueba 26 puertos conocidos salvo que se le indique otra cosa.
- **Panel sin conexión:** un único HTML autocontenido, en español e inglés, con tema claro y oscuro y exportación a CSV.

## Cómo funciona

1. **Descubrimiento:** un ping a cada dirección (64 a la vez). Aunque un equipo ignore el ping (los Windows y los móviles lo hacen por defecto), el sistema tiene que resolver su MAC por ARP antes, así que al leer la tabla ARP aparece igualmente. En una red doméstica real encuentra 18 dispositivos donde el ping solo encuentra 11.
2. **Identificación:** el fabricante sale del prefijo de la MAC (registro público del IEEE). Las MAC "privadas" aleatorias de los móviles se detectan y se marcan. El DNS inverso añade el nombre del equipo.
3. **Puertos:** comprobación TCP asíncrona de 26 puertos comunes (SSH, Telnet, HTTP/S, SMB, RDP, VNC, impresión, MQTT, RTSP, Chromecast, Plex…).
4. **Clasificación y avisos:** Telnet abierto es crítico; FTP, VNC, RDP, MQTT sin cifrar, paneles web solo por HTTP y dispositivos nuevos son advertencias.
5. **Historial:** cada dispositivo se guarda en `known_devices.json` por su MAC. El primer escaneo es la referencia; a partir de ahí se marcan los nuevos.

## Uso rápido

```bash
git clone https://github.com/DavidGoRi/NetScope.git
cd NetScope
python -m pip install .
netscope update-oui        # una vez: descarga el registro de fabricantes del IEEE
netscope scan              # escanea la red de este equipo
```

El panel se guarda en `output/netscope-report.html` y cada escaneo, en JSON, en `output/scans/`. Las opciones (`--cidr`, `--ports`, `--json`, `--fail-on`…) están explicadas en el [README en inglés](README.md#usage).

## Uso responsable

Escanea solo redes que sean tuyas o que tengas permiso para revisar.

## Licencia

[MIT](LICENSE)
