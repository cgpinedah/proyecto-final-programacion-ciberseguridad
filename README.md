```
  ____      _                ____                     _
 / ___|   _| |__   ___ _ __ / ___|_   _  __ _ _ __ __| |
| |  | | | | '_ \ / _ \ '__| |  _| | | |/ _` | '__/ _` |
| |__| |_| | |_) |  __/ |  | |_| | |_| | (_| | | | (_| |
 \____\__, |_.__/ \___|_|   \____|\__,_|\__,_|_|  \__,_|
      |___/

    _                _
   / \   _ __   __ _| |_   _ _______ _ __
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                       |___/
```

Programa en Python por linea de comandos. Recibe un archivo `.txt`, valida y sanitiza su contenido, y genera un reporte `.txt` con los errores encontrados.

## Uso

Para ejecutar el programa hay que entrar al entorno virtual:

```bash
source venv/bin/activate
python main.py
```

El programa pide la ruta del archivo y muestra este menu:

1. `ingestion.py`: lee el archivo, normaliza los datos y controla errores de entrada.
2. `validation.py`: sanitiza cadenas y valida campos obligatorios y formatos.
3. `integrity.py`: calcula y compara hashes de evidencia.
4. `network_analyzer.py`: analiza metadatos TCP/HTTP o registros de trafico autorizados.
5. Salir.

Cada opcion llama a `ejecutar(ruta)` en su archivo. `ruta` es el path del `.txt` ingresado.

Hay un log de ejemplo en `output/test.txt`.
