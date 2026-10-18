#!/usr/bin/env python3
"""
ingestion.py

Modulo de ingesta segura de archivos .txt y .csv para el proyecto final
de Programacion para Ciberseguridad.

Rol dentro del proyecto (ver README.md):
    main.py pide al usuario la ruta de un archivo .txt (o .csv) y, segun
    la opcion elegida en el menu, llama a `ejecutar(ruta)` del modulo
    correspondiente. Este modulo implementa la opcion 1: "lee el archivo,
    normaliza los datos y controla errores de entrada".

Responsabilidades de este modulo:
    - Validar la ruta recibida (existencia, tipo, extension, tamano).
    - Leer archivos .txt (delimitados) y .csv.
    - Normalizar texto, encabezados, fechas, numeros y correos.
    - Registrar eventos de seguridad y errores en logs/security_events.log.
    - Generar un archivo CSV normalizado y un reporte .txt de errores.

Uso como modulo (desde main.py):
    import ingestion
    resultado = ingestion.ejecutar(ruta)

Uso independiente desde linea de comandos:
    python ingestion.py data/input/clientes.csv
    python ingestion.py --input-dir data/input --output-dir data/output --batch
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS = {".txt", ".csv"}

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
MAX_LINE_LENGTH = 10_000
MAX_LOG_VALUE_LENGTH: int = 200
MAX_PATH_LENGTH: int = 4096

DEFAULT_INPUT_DIR = Path("data/input")
DEFAULT_OUTPUT_DIR = Path("data/output")
DEFAULT_LOG_DIR = Path("logs")
LOG_FILE_NAME = "security_events.log"

INPUT_ENCODING: str = "utf-8"
OUTPUT_ENCODING = "utf-8"
CSV_DELIMITER = ","
TXT_FIELD_DELIMITER: str = "|"

EMPTY_VALUES: set[str] = {"", "-", "null", "none", "na", "n/a"}

ACCEPTED_DATE_FORMATS: tuple[str, ...] = (
    "%Y-%m-%d",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%Y/%m/%d",
)
STANDARD_DATE_FORMAT: str = "%Y-%m-%d"

# Campos obligatorios del esquema esperado. Ajustar segun los datos reales
# del proyecto (p. ej. agregar "fecha", "monto", etc. si son obligatorios).
REQUIRED_FIELDS: tuple[str, ...] = ("id",)

CONTROL_CHARACTERS_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
MULTIPLE_WHITESPACE_PATTERN = re.compile(r"\s+")
INVALID_FIELD_NAME_PATTERN = re.compile(r"[^a-z0-9_]+")
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.(/|\\|$)")


# ---------------------------------------------------------------------------
# Excepciones personalizadas
# ---------------------------------------------------------------------------

class IngestionError(Exception):
    """Error controlado durante el proceso de ingesta."""


class SecurityEventError(IngestionError):
    """Error que ademas debe registrarse como evento de seguridad."""


# ---------------------------------------------------------------------------
# Logging y eventos de seguridad
# ---------------------------------------------------------------------------

def configure_logging(log_dir: Path = DEFAULT_LOG_DIR) -> logging.Logger:
    """Configura (una sola vez) un logger de archivo para eventos de seguridad."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("ingestion")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(event)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def sanitize_for_log(value: Any, max_length: int = MAX_LOG_VALUE_LENGTH) -> str:
    """Neutraliza datos no confiables antes de escribirlos en el log.

    Evita inyeccion de saltos de linea (log forging), caracteres de control
    y trunca valores excesivamente largos.
    """
    safe_value = str(value)
    safe_value = safe_value.replace("\r", "\\r").replace("\n", "\\n")
    safe_value = CONTROL_CHARACTERS_PATTERN.sub("", safe_value)
    safe_value = safe_value.replace("|", "\\|")
    if len(safe_value) > max_length:
        safe_value = safe_value[:max_length] + "...[truncado]"
    return safe_value


def log_security_event(
    logger: logging.Logger,
    event: str,
    description: str,
    level: int = logging.WARNING,
    **context: Any,
) -> None:
    """Registra un evento de seguridad estructurado y saneado."""
    try:
        safe_context = {
            key: sanitize_for_log(value) for key, value in context.items()
        }
        logger.log(
            level,
            sanitize_for_log(description),
            extra={"event": event, **safe_context},
        )
    except Exception as logging_error:  # el logging nunca debe tumbar el flujo
        print(
            f"No fue posible escribir el evento de seguridad '{event}': {logging_error}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Normalizacion
# ---------------------------------------------------------------------------

def normalize_text(value: Any) -> str:
    """Normaliza texto: Unicode NFC, caracteres de control y espacios."""
    if value is None:
        return ""
    normalized_value = str(value)
    normalized_value = unicodedata.normalize("NFC", normalized_value)
    normalized_value = normalized_value.replace("\r\n", " ")
    normalized_value = normalized_value.replace("\r", " ")
    normalized_value = normalized_value.replace("\n", " ")
    normalized_value = CONTROL_CHARACTERS_PATTERN.sub("", normalized_value)
    normalized_value = normalized_value.strip()
    normalized_value = MULTIPLE_WHITESPACE_PATTERN.sub(" ", normalized_value)
    return normalized_value


def normalize_field_name(raw_name: Any) -> str:
    """Convierte encabezados en nombres de campo consistentes (snake_case)."""
    normalized_name = normalize_text(raw_name).lower()
    normalized_name = normalized_name.replace(" ", "_").replace("-", "_")
    normalized_name = INVALID_FIELD_NAME_PATTERN.sub("", normalized_name)
    return normalized_name or "campo_sin_nombre"


def normalize_empty_value(value: str) -> str | None:
    """Convierte representaciones comunes de valor vacio en None."""
    if value.strip().lower() in EMPTY_VALUES:
        return None
    return value


def normalize_number(raw_value: Any, field_name: str = "numero") -> float | None:
    """Normaliza un valor numerico y valida su conversion."""
    normalized_value = normalize_text(raw_value)
    if normalized_value == "":
        return None
    cleaned_value = normalized_value.replace("$", "").replace("\u20ac", "")
    cleaned_value = cleaned_value.replace(",", ".")
    try:
        numeric_value = float(cleaned_value)
    except ValueError as error:
        raise IngestionError(
            f"El campo '{field_name}' no contiene un numero valido."
        ) from error
    return numeric_value


def normalize_date(raw_value: Any, field_name: str = "fecha") -> str | None:
    """Normaliza fechas al formato estandar YYYY-MM-DD."""
    normalized_value = normalize_text(raw_value)
    if normalized_value == "":
        return None
    for date_format in ACCEPTED_DATE_FORMATS:
        try:
            parsed_date = datetime.strptime(normalized_value, date_format)
            return parsed_date.strftime(STANDARD_DATE_FORMAT)
        except ValueError:
            continue
    raise IngestionError(
        f"El campo '{field_name}' no tiene una fecha valida: "
        f"formatos aceptados: {', '.join(ACCEPTED_DATE_FORMATS)}."
    )


def normalize_email(raw_value: Any, field_name: str = "correo") -> str | None:
    """Normaliza y valida de forma basica un correo electronico."""
    normalized_value = normalize_text(raw_value)
    if normalized_value == "":
        return None
    if normalized_value.count("@") != 1:
        raise IngestionError(
            f"El campo '{field_name}' debe contener exactamente un '@'."
        )
    local_part, domain_part = normalized_value.split("@", 1)
    if not local_part or "." not in domain_part:
        raise IngestionError(
            f"El campo '{field_name}' no tiene un formato de correo valido."
        )
    if len(normalized_value) > 254:
        raise IngestionError(
            f"El campo '{field_name}' excede la longitud maxima permitida."
        )
    return f"{local_part}@{domain_part.lower()}"


def normalize_record(
    raw_record: dict[str, Any],
    logger: logging.Logger,
    source_file: Path,
    line_number: int,
    error_log: list[str] | None = None,
) -> dict[str, Any] | None:
    """Normaliza un registro completo y aplica validaciones por campo.

    Si el registro no pasa las validaciones, se registra como evento de
    seguridad (INPUT_VALIDATION_FAIL), opcionalmente se agregan los errores
    a `error_log` (para el reporte .txt) y se devuelve None para descartarlo.
    """
    normalized_record: dict[str, Any] = {}
    validation_errors: list[str] = []

    for raw_key, raw_value in raw_record.items():
        field_name = normalize_field_name(raw_key)
        normalized_value: str | None = normalize_text(raw_value)
        normalized_value = normalize_empty_value(normalized_value)
        normalized_record[field_name] = normalized_value

    for required_field in REQUIRED_FIELDS:
        if normalized_record.get(required_field) in (None, ""):
            validation_errors.append(
                f"Campo obligatorio ausente o vacio: '{required_field}'."
            )

    if "fecha" in normalized_record:
        try:
            normalized_record["fecha"] = normalize_date(
                normalized_record["fecha"], field_name="fecha"
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if "monto" in normalized_record:
        try:
            normalized_record["monto"] = normalize_number(
                normalized_record["monto"], field_name="monto"
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if "correo" in normalized_record:
        try:
            normalized_record["correo"] = normalize_email(
                normalized_record["correo"], field_name="correo"
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if validation_errors:
        mensaje = f"Linea {line_number}: {' '.join(validation_errors)}"
        log_security_event(
            logger=logger,
            event="INPUT_VALIDATION_FAIL",
            description="Registro rechazado por validacion de entrada.",
            level=logging.WARNING,
            archivo=source_file.name,
            linea=line_number,
            errores="; ".join(validation_errors),
        )
        if error_log is not None:
            error_log.append(mensaje)
        return None

    return normalized_record


# ---------------------------------------------------------------------------
# Validacion de archivos
# ---------------------------------------------------------------------------

def validate_input_path(
    input_path: Path,
    logger: logging.Logger,
    allowed_root: Path | None = None,
) -> Path:
    """Valida existencia, tipo, extension, ubicacion y tamano del archivo.

    `allowed_root`, si se indica, obliga a que el archivo este contenido
    dentro de ese directorio (util en el modo por lotes). En el modo
    interactivo (`ejecutar`) no se restringe a un directorio fijo porque
    el usuario puede indicar cualquier ruta valida, pero se registran como
    evento de seguridad los intentos de path traversal (p. ej. "..").
    """
    raw_path_text = str(input_path)

    if "\x00" in raw_path_text:
        raise SecurityEventError("La ruta contiene un byte nulo no permitido.")

    if len(raw_path_text) > MAX_PATH_LENGTH:
        raise SecurityEventError("La ruta excede la longitud maxima permitida.")

    if PATH_TRAVERSAL_PATTERN.search(raw_path_text):
        log_security_event(
            logger=logger,
            event="PATH_TRAVERSAL_ATTEMPT",
            description="Se detecto un patron de salida de directorio ('..') en la ruta.",
            level=logging.WARNING,
            ruta=raw_path_text,
        )

    resolved_path = input_path.expanduser().resolve()

    if allowed_root is not None:
        allowed_root_resolved = allowed_root.resolve()
        is_contained = False
        try:
            is_contained = resolved_path.is_relative_to(allowed_root_resolved)
        except AttributeError:  # Python < 3.9
            is_contained = str(resolved_path).startswith(str(allowed_root_resolved))
        if not is_contained:
            raise SecurityEventError(
                f"La ruta '{input_path}' esta fuera del directorio autorizado."
            )

    if not resolved_path.exists():
        raise IngestionError(f"El archivo no existe: '{input_path}'.")

    if not resolved_path.is_file():
        raise IngestionError(f"La ruta no corresponde a un archivo: '{input_path}'.")

    file_extension = resolved_path.suffix.lower()
    if file_extension not in SUPPORTED_EXTENSIONS:
        raise SecurityEventError(f"Extension no permitida: '{file_extension}'.")

    try:
        file_size = resolved_path.stat().st_size
    except OSError as error:
        raise IngestionError(
            f"No fue posible consultar el tamano del archivo '{input_path}'."
        ) from error

    if file_size > MAX_FILE_SIZE_BYTES:
        raise SecurityEventError(
            f"El archivo excede el tamano maximo permitido "
            f"({MAX_FILE_SIZE_BYTES} bytes)."
        )

    if file_size == 0:
        raise IngestionError(f"El archivo '{input_path}' esta vacio.")

    return resolved_path


# ---------------------------------------------------------------------------
# Lectura de archivos
# ---------------------------------------------------------------------------

def read_csv_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo CSV y entrega registros con encabezados normalizados."""
    try:
        with file_path.open(mode="r", encoding=INPUT_ENCODING, newline="") as file_handler:
            reader = csv.DictReader(file_handler, delimiter=CSV_DELIMITER)
            if not reader.fieldnames:
                raise IngestionError(
                    f"El archivo CSV no contiene encabezados: '{file_path.name}'."
                )

            normalized_headers = [normalize_field_name(header) for header in reader.fieldnames]

            for row_number, raw_row in enumerate(reader, start=2):
                try:
                    normalized_row = {
                        normalized_headers[index]: value
                        for index, value in enumerate(raw_row.values())
                        if index < len(normalized_headers)
                    }
                except (TypeError, ValueError, IndexError) as error:
                    raise IngestionError(
                        f"Fila {row_number} con estructura invalida."
                    ) from error
                yield normalized_row
    except UnicodeDecodeError as error:
        raise IngestionError(
            f"Error de codificacion al leer '{file_path.name}': {error}"
        ) from error
    except csv.Error as error:
        raise IngestionError(
            f"Error al analizar el archivo CSV '{file_path.name}': {error}"
        ) from error


def read_txt_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo TXT delimitado por '|' y entrega registros crudos."""
    try:
        with file_path.open(mode="r", encoding=INPUT_ENCODING) as file_handler:
            for line_number, raw_line in enumerate(file_handler, start=1):
                if len(raw_line) > MAX_LINE_LENGTH:
                    raise SecurityEventError(
                        f"Linea {line_number} excede la longitud maxima permitida."
                    )
                normalized_line = normalize_text(raw_line)
                if not normalized_line:
                    continue
                fields = normalized_line.split(TXT_FIELD_DELIMITER)
                yield {f"campo_{index}": value for index, value in enumerate(fields, start=1)}
    except UnicodeDecodeError as error:
        raise IngestionError(
            f"Error de codificacion al leer '{file_path.name}': {error}"
        ) from error
    except OSError as error:
        raise IngestionError(
            f"Error de acceso al archivo '{file_path.name}': {error}"
        ) from error


def read_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Selecciona el lector adecuado segun la extension del archivo."""
    file_extension = file_path.suffix.lower()
    if file_extension == ".csv":
        return read_csv_file(file_path)
    if file_extension == ".txt":
        return read_txt_file(file_path)
    raise SecurityEventError(f"Formato no soportado: '{file_extension}'.")


# ---------------------------------------------------------------------------
# Escritura de salida
# ---------------------------------------------------------------------------

def write_normalized_csv(records: Iterable[dict[str, Any]], output_path: Path) -> int:
    """Escribe registros normalizados en un archivo CSV. Devuelve el total escrito."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written_count = 0
    fieldnames: list[str] | None = None
    writer: csv.DictWriter | None = None

    try:
        with output_path.open(mode="w", encoding=OUTPUT_ENCODING, newline="") as file_handler:
            for record in records:
                if fieldnames is None:
                    fieldnames = list(record.keys())
                    writer = csv.DictWriter(
                        file_handler,
                        fieldnames=fieldnames,
                        delimiter=CSV_DELIMITER,
                        extrasaction="ignore",
                    )
                    writer.writeheader()
                writer.writerow(record)
                written_count += 1
    except OSError as error:
        raise IngestionError(
            f"Error al escribir el archivo de salida '{output_path.name}': {error}"
        ) from error
    except csv.Error as error:
        raise IngestionError(
            f"Error al escribir una fila en '{output_path.name}': {error}"
        ) from error

    return written_count


def write_error_report(
    source_file: Path,
    output_path: Path,
    total_leidos: int,
    total_validos: int,
    errores: list[str],
) -> None:
    """Genera el reporte .txt con los errores encontrados durante el analisis."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")

    lineas = [
        "REPORTE DE INGESTA DE DATOS",
        "=" * 40,
        f"Archivo analizado : {source_file.name}",
        f"Fecha de analisis : {timestamp}",
        f"Registros leidos  : {total_leidos}",
        f"Registros validos : {total_validos}",
        f"Registros con error: {len(errores)}",
        "",
    ]

    if errores:
        lineas.append("Detalle de errores:")
        lineas.append("-" * 40)
        lineas.extend(errores)
    else:
        lineas.append("No se encontraron errores durante el analisis.")

    try:
        output_path.write_text("\n".join(lineas) + "\n", encoding=OUTPUT_ENCODING)
    except OSError as error:
        raise IngestionError(
            f"Error al escribir el reporte '{output_path.name}': {error}"
        ) from error


# ---------------------------------------------------------------------------
# Procesamiento de un archivo
# ---------------------------------------------------------------------------

def process_file(
    logger: logging.Logger,
    file_path: Path,
    output_dir: Path,
    allowed_root: Path | None = None,
) -> dict[str, Any]:
    """Valida, lee, normaliza y exporta un archivo individual.

    Devuelve un diccionario con el resultado del procesamiento, incluyendo
    las rutas del CSV normalizado y del reporte .txt de errores.
    """
    result: dict[str, Any] = {
        "archivo": file_path.name,
        "estado": "error",
        "registros_leidos": 0,
        "registros_validos": 0,
    }

    try:
        validated_path = validate_input_path(file_path, logger=logger, allowed_root=allowed_root)
        output_csv_path = output_dir / f"{validated_path.stem}_normalized.csv"
        report_path = output_dir / f"{validated_path.stem}_report.txt"

        raw_records = read_file(validated_path)
        valid_records: list[dict[str, Any]] = []
        errores: list[str] = []
        total_leidos = 0

        for line_number, raw_record in enumerate(raw_records, start=1):
            total_leidos += 1
            normalized_record = normalize_record(
                raw_record=raw_record,
                logger=logger,
                source_file=validated_path,
                line_number=line_number,
                error_log=errores,
            )
            if normalized_record is not None:
                valid_records.append(normalized_record)

        written_count = write_normalized_csv(valid_records, output_csv_path)
        write_error_report(
            source_file=validated_path,
            output_path=report_path,
            total_leidos=total_leidos,
            total_validos=written_count,
            errores=errores,
        )

        result["estado"] = "success"
        result["registros_leidos"] = total_leidos
        result["registros_validos"] = written_count
        result["salida_csv"] = str(output_csv_path)
        result["reporte_errores"] = str(report_path)

        log_security_event(
            logger=logger,
            event="INGESTION_SUCCESS",
            description="Archivo procesado correctamente.",
            level=logging.INFO,
            archivo=validated_path.name,
            registros_leidos=total_leidos,
            registros_validos=written_count,
            salida=output_csv_path.name,
        )

    except SecurityEventError as error:
        result["error"] = str(error)
        log_security_event(
            logger=logger,
            event="SECURITY_EVENT",
            description=str(error),
            level=logging.ERROR,
            archivo=file_path.name,
        )

    except IngestionError as error:
        result["error"] = str(error)
        log_security_event(
            logger=logger,
            event="INGESTION_FAILURE",
            description=str(error),
            level=logging.ERROR,
            archivo=file_path.name,
        )

    except Exception as error:  # ultima barrera: nunca dejar un error sin registrar
        result["error"] = f"Error inesperado: {error}"
        log_security_event(
            logger=logger,
            event="UNEXPECTED_ERROR",
            description=result["error"],
            level=logging.CRITICAL,
            archivo=file_path.name,
        )

    return result


# ---------------------------------------------------------------------------
# Punto de entrada usado por main.py (opcion 1 del menu)
# ---------------------------------------------------------------------------

def ejecutar(
    ruta: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    log_dir: Path = DEFAULT_LOG_DIR,
) -> dict[str, Any]:
    """Punto de entrada que main.py invoca para la opcion 'ingestion'.

    Lee el archivo .txt o .csv indicado en `ruta`, normaliza sus datos y
    controla los errores de entrada registrando eventos de seguridad.
    Genera un CSV normalizado y un reporte .txt de errores en `output_dir`,
    e imprime un resumen por consola para el usuario del menu.

    Devuelve el diccionario de resultado de `process_file`, por si en el
    futuro main.py quisiera usar el valor de retorno. Actualmente main.py
    llama `funcion(ruta)` sin capturar el resultado y sin ningun try/except
    alrededor de la llamada, por lo que esta funcion NUNCA debe propagar
    una excepcion: cualquier fallo inesperado se atrapa, se registra como
    evento de seguridad y se informa por consola, para no tumbar el menu.
    """
    resultado: dict[str, Any] = {"archivo": ruta, "estado": "error"}

    try:
        logger = configure_logging(log_dir)
    except Exception as error:
        print("No fue posible inicializar el log de seguridad.")
        print(f"  Error: {error}")
        resultado["error"] = f"No fue posible inicializar el logging: {error}"
        return resultado

    try:
        log_security_event(
            logger=logger,
            event="INGESTION_START",
            description="Inicio del proceso de ingesta.",
            level=logging.INFO,
            archivo=ruta,
        )

        resultado = process_file(
            logger=logger,
            file_path=Path(ruta),
            output_dir=output_dir,
        )

        if resultado["estado"] == "success":
            print("Ingesta completada correctamente.")
            print(f"  Archivo analizado   : {resultado['archivo']}")
            print(f"  Registros leidos    : {resultado['registros_leidos']}")
            print(f"  Registros validos   : {resultado['registros_validos']}")
            print(f"  CSV normalizado     : {resultado['salida_csv']}")
            print(f"  Reporte de errores  : {resultado['reporte_errores']}")
        else:
            print("La ingesta no se pudo completar.")
            print(f"  Archivo  : {resultado['archivo']}")
            print(f"  Error    : {resultado.get('error', 'Error desconocido')}")

        log_security_event(
            logger=logger,
            event="INGESTION_END",
            description="Fin del proceso de ingesta.",
            level=logging.INFO,
            archivo=ruta,
            estado=resultado["estado"],
        )

    except Exception as error:
        # Barrera final: ejecutar(ruta) no debe nunca lanzar, porque
        # main.py la invoca sin try/except y eso detendria todo el menu.
        resultado["estado"] = "error"
        resultado["error"] = f"Error inesperado no controlado: {error}"
        log_security_event(
            logger=logger,
            event="UNEXPECTED_ERROR",
            description=resultado["error"],
            level=logging.CRITICAL,
            archivo=ruta,
        )
        print("Ocurrio un error inesperado durante la ingesta.")
        print(f"  Archivo  : {ruta}")
        print(f"  Error    : {error}")

    return resultado


# ---------------------------------------------------------------------------
# Modo por lotes (opcional, para pruebas fuera del menu de main.py)
# ---------------------------------------------------------------------------

def discover_input_files(input_dir: Path) -> list[Path]:
    """Encuentra archivos .txt y .csv en el directorio de entrada."""
    if not input_dir.exists():
        raise IngestionError(f"El directorio de entrada no existe: '{input_dir}'.")
    if not input_dir.is_dir():
        raise IngestionError(f"La ruta de entrada no es un directorio: '{input_dir}'.")

    input_files = [
        candidate
        for candidate in input_dir.iterdir()
        if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    return sorted(input_files)


def run_batch(input_dir: Path, output_dir: Path, log_dir: Path, fail_fast: bool) -> int:
    """Procesa todos los .txt/.csv de un directorio (modo utilitario de pruebas)."""
    logger = configure_logging(log_dir)

    try:
        input_files = discover_input_files(input_dir)
    except IngestionError as error:
        log_security_event(logger, "INGESTION_FAILURE", str(error), level=logging.ERROR)
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if not input_files:
        log_security_event(
            logger, "NO_INPUT_FILES",
            "No se encontraron archivos .txt o .csv para procesar.",
            level=logging.WARNING, input_dir=str(input_dir),
        )
        print("No se encontraron archivos .txt o .csv para procesar.")
        return 0

    procesados = fallidos = total_registros = 0

    for input_file in input_files:
        resultado = process_file(
            logger=logger,
            file_path=input_file,
            output_dir=output_dir,
            allowed_root=input_dir,
        )
        if resultado["estado"] == "success":
            procesados += 1
            total_registros += resultado["registros_validos"]
        else:
            fallidos += 1
            print(f"  [ERROR] {input_file.name}: {resultado.get('error')}")
            if fail_fast:
                log_security_event(
                    logger, "FAIL_FAST_ACTIVATED",
                    "Ejecucion detenida por --fail-fast tras un error.",
                    level=logging.ERROR, archivo=input_file.name,
                )
                return 1

    print(f"Archivos procesados: {procesados} | fallidos: {fallidos} | registros validos: {total_registros}")

    log_security_event(
        logger, "INGESTION_SUMMARY", "Resumen final de ingesta por lotes.",
        level=logging.INFO,
        archivos_procesados=procesados, archivos_fallidos=fallidos,
        registros_totales=total_registros,
    )

    return 0 if fallidos == 0 else 1


def parse_arguments() -> argparse.Namespace:
    """Define y procesa los argumentos de linea de comandos del modo standalone."""
    parser = argparse.ArgumentParser(description="Ingesta segura de archivos TXT y CSV.")
    parser.add_argument(
        "ruta",
        nargs="?",
        default=None,
        help="Ruta de un archivo .txt o .csv a procesar (modo equivalente a ejecutar(ruta)).",
    )
    parser.add_argument("--batch", action="store_true", help="Procesa todos los archivos de --input-dir.")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR, help="Directorio de entrada (modo --batch).")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Directorio de salida.")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR, help="Directorio del log de seguridad.")
    parser.add_argument("--fail-fast", action="store_true", help="Detiene el lote ante el primer error.")
    return parser.parse_args()


def main() -> int:
    """Permite ejecutar este modulo de forma independiente para pruebas."""
    arguments = parse_arguments()

    if arguments.batch:
        return run_batch(
            input_dir=arguments.input_dir,
            output_dir=arguments.output_dir,
            log_dir=arguments.log_dir,
            fail_fast=arguments.fail_fast,
        )

    if not arguments.ruta:
        print("Debe indicar la ruta de un archivo .txt o .csv, o usar --batch.", file=sys.stderr)
        return 1

    resultado = ejecutar(arguments.ruta, output_dir=arguments.output_dir, log_dir=arguments.log_dir)
    return 0 if resultado["estado"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())