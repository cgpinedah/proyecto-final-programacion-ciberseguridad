#!/usr/bin/env python3

"""
ingestion.py

Ingesta segura de archivos .txt y .csv.

- Lee archivos desde un directorio de entrada autorizado.
- Normaliza encabezados, texto, fechas, números y correos.
- Genera un archivo CSV normalizado por cada archivo de entrada.
- Registra eventos de seguridad y errores en logs/security_events.log.

Uso:
    python ingestion.py
    python ingestion.py --input-dir data/input --output-dir data/output
    python ingestion.py --fail-fast
"""
from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

"""CONSTANTES"""
SUPPORTED_EXTENSIONS = {".txt", ".csv"}

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
MAX_LINE_LENGTH = 10_000
MAX_LOG_VALUE_LENGTH: int = 200

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

REQUIRED_FIELDS: tuple[str, ...] = ("id",)

CONTROL_CHARACTERS_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
MULTIPLE_WHITESPACE_PATTERN = re.compile(r"\s+")
INVALID_FIELD_NAME_PATTERN = re.compile(r"[^a-z0-9_]+")


# ---------------------------------------------------------------------------
# Excepciones personalizadas
# ---------------------------------------------------------------------------


class IngestionError(Exception):
    """Error controlado durante el proceso de ingesta."""


class SecurityEventError(IngestionError):
    """Error que debe registrarse como evento de seguridad."""


# ---------------------------------------------------------------------------
# Logging y eventos de seguridad
# ---------------------------------------------------------------------------


def configure_logging(log_dir: Path) -> logging.Logger:
    """Configura un logger de archivo para eventos de seguridad."""
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
    """Neutraliza datos no confiables antes de escribirlos en el log."""
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
    """Registra un evento de seguridad estructurado y seguro."""
    try:
        safe_context = {
            key: sanitize_for_log(value)
            for key, value in context.items()
        }
        logger.log(
            level,
            sanitize_for_log(description),
            extra={"event": event, **safe_context},
        )
    except Exception as logging_error:
        print(
            f"No fue posible escribir el evento de seguridad '{event}': {logging_error}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Normalización
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
    """Convierte encabezados en nombres de campo consistentes."""
    normalized_name = normalize_text(raw_name).lower()
    normalized_name = normalized_name.replace(" ", "_").replace("-", "_")
    normalized_name = INVALID_FIELD_NAME_PATTERN.sub("", normalized_name)

    return normalized_name or "campo_sin_nombre"


def normalize_empty_value(value: str) -> str | None:
    """Convierte representaciones comunes de valor vacío en None."""
    if value.strip().lower() in EMPTY_VALUES:
        return None

    return value


def normalize_number(
    raw_value: Any,
    field_name: str = "numero",
) -> float | None:
    """Normaliza un valor numérico y valida su conversión."""
    normalized_value = normalize_text(raw_value)

    if normalized_value == "":
        return None

    cleaned_value = normalized_value.replace("$", "").replace("€", "")
    cleaned_value = cleaned_value.replace(",", ".")

    try:
        numeric_value = float(cleaned_value)
    except ValueError as error:
        raise IngestionError(
            f"El campo '{field_name}' no contiene un número válido."
        ) from error

    return numeric_value


def normalize_date(
    raw_value: Any,
    field_name: str = "fecha",
) -> str | None:
    """Normaliza fechas al formato estándar YYYY-MM-DD."""
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
        f"El campo '{field_name}' no tiene una fecha válida: "
        f"formatos aceptados: {', '.join(ACCEPTED_DATE_FORMATS)}."
    )


def normalize_email(raw_value: Any, field_name: str = "correo") -> str | None:
    """Normaliza y valida de forma básica un correo electrónico."""
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
            f"El campo '{field_name}' no tiene un formato de correo válido."
        )

    if len(normalized_value) > 254:
        raise IngestionError(
            f"El campo '{field_name}' excede la longitud máxima permitida."
        )

    return f"{local_part}@{domain_part.lower()}"


def normalize_record(
    raw_record: dict[str, Any],
    logger: logging.Logger,
    source_file: Path,
    line_number: int,
) -> dict[str, Any] | None:
    """Normaliza un registro completo y aplica validaciones por campo."""
    normalized_record: dict[str, Any] = {}
    validation_errors: list[str] = []

    for raw_key, raw_value in raw_record.items():
        field_name = normalize_field_name(raw_key)
        normalized_value = normalize_text(raw_value)
        normalized_value = normalize_empty_value(normalized_value)

        normalized_record[field_name] = normalized_value

    for required_field in REQUIRED_FIELDS:
        if normalized_record.get(required_field) in (None, ""):
            validation_errors.append(
                f"Campo obligatorio ausente o vacío: '{required_field}'."
            )

    if "fecha" in normalized_record:
        try:
            normalized_record["fecha"] = normalize_date(
                normalized_record["fecha"],
                field_name="fecha",
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if "monto" in normalized_record:
        try:
            normalized_record["monto"] = normalize_number(
                normalized_record["monto"],
                field_name="monto",
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if "correo" in normalized_record:
        try:
            normalized_record["correo"] = normalize_email(
                normalized_record["correo"],
                field_name="correo",
            )
        except IngestionError as error:
            validation_errors.append(str(error))

    if validation_errors:
        log_security_event(
            logger=logger,
            event="INPUT_VALIDATION_FAIL",
            description="Registro rechazado por validación de entrada.",
            level=logging.WARNING,
            archivo=source_file.name,
            linea=line_number,
            errores="; ".join(validation_errors),
        )
        return None

    return normalized_record


# ---------------------------------------------------------------------------
# Validación de archivos
# ---------------------------------------------------------------------------


def validate_input_path(input_path: Path) -> Path:
    """Valida existencia, tipo, extensión, ubicación y tamaño del archivo."""
    resolved_path = input_path.resolve()
    allowed_root = DEFAULT_INPUT_DIR.resolve()

    try:
        if not resolved_path.is_relative_to(allowed_root):
            raise SecurityEventError(
                f"La ruta '{input_path}' está fuera del directorio autorizado."
            )
    except AttributeError:
        if not str(resolved_path).startswith(str(allowed_root)):
            raise SecurityEventError(
                f"La ruta '{input_path}' está fuera del directorio autorizado."
            ) from None

    if not resolved_path.exists():
        raise IngestionError(f"El archivo no existe: '{input_path}'.")

    if not resolved_path.is_file():
        raise IngestionError(f"La ruta no corresponde a un archivo: '{input_path}'.")

    file_extension = resolved_path.suffix.lower()

    if file_extension not in SUPPORTED_EXTENSIONS:
        raise SecurityEventError(
            f"Extensión no permitida: '{file_extension}'."
        )

    try:
        file_size = resolved_path.stat().st_size
    except OSError as error:
        raise IngestionError(
            f"No fue posible consultar el tamaño del archivo '{input_path}'."
        ) from error

    if file_size > MAX_FILE_SIZE_BYTES:
        raise SecurityEventError(
            f"El archivo excede el tamaño máximo permitido "
            f"({MAX_FILE_SIZE_BYTES} bytes)."
        )

    return resolved_path


# ---------------------------------------------------------------------------
# Lectura de archivos
# ---------------------------------------------------------------------------


def read_csv_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo CSV y entrega registros normalizados."""
    try:
        with file_path.open(
            mode="r",
            encoding=INPUT_ENCODING,
            newline="",
        ) as file_handler:
            reader = csv.DictReader(file_handler, delimiter=CSV_DELIMITER)

            if not reader.fieldnames:
                raise IngestionError(
                    f"El archivo CSV no contiene encabezados: '{file_path.name}'."
                )

            normalized_headers = [
                normalize_field_name(header) for header in reader.fieldnames
            ]

            for row_number, raw_row in enumerate(reader, start=2):
                try:
                    normalized_row = {
                        normalized_headers[index]: value
                        for index, value in enumerate(raw_row.values())
                    }
                except (TypeError, ValueError) as error:
                    raise IngestionError(
                        f"Fila {row_number} con estructura inválida."
                    ) from error

                yield normalized_row

    except UnicodeDecodeError as error:
        raise IngestionError(
            f"Error de codificación al leer '{file_path.name}': {error}"
        ) from error
    except csv.Error as error:
        raise IngestionError(
            f"Error al analizar el archivo CSV '{file_path.name}': {error}"
        ) from error


def read_txt_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Lee un archivo TXT delimitado y entrega registros normalizados."""
    try:
        with file_path.open(
            mode="r",
            encoding=INPUT_ENCODING,
        ) as file_handler:
            for line_number, raw_line in enumerate(file_handler, start=1):
                if len(raw_line) > MAX_LINE_LENGTH:
                    raise SecurityEventError(
                        f"Línea {line_number} excede la longitud máxima permitida."
                    )

                normalized_line = normalize_text(raw_line)

                if not normalized_line:
                    continue

                fields = normalized_line.split(TXT_FIELD_DELIMITER)

                yield {
                    f"campo_{index}": value
                    for index, value in enumerate(fields, start=1)
                }

    except UnicodeDecodeError as error:
        raise IngestionError(
            f"Error de codificación al leer '{file_path.name}': {error}"
        ) from error
    except OSError as error:
        raise IngestionError(
            f"Error de acceso al archivo '{file_path.name}': {error}"
        ) from error


def read_file(file_path: Path) -> Iterator[dict[str, Any]]:
    """Selecciona el lector adecuado según la extensión del archivo."""
    file_extension = file_path.suffix.lower()

    if file_extension == ".csv":
        return read_csv_file(file_path)

    if file_extension == ".txt":
        return read_txt_file(file_path)

    raise SecurityEventError(
        f"Formato no soportado: '{file_extension}'."
    )


# ---------------------------------------------------------------------------
# Escritura de salida
# ---------------------------------------------------------------------------


def write_normalized_csv(
    records: Iterable[dict[str, Any]],
    output_path: Path,
) -> int:
    """Escribe registros normalizados en un archivo CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    written_count = 0
    fieldnames: list[str] | None = None
    writer: csv.DictWriter | None = None

    try:
        with output_path.open(
            mode="w",
            encoding=OUTPUT_ENCODING,
            newline="",
        ) as file_handler:
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

                if writer is None:
                    raise IngestionError(
                        "No fue posible inicializar el escritor CSV."
                    )

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


# ---------------------------------------------------------------------------
# Procesamiento por archivo
# ---------------------------------------------------------------------------


def process_file(
    logger: logging.Logger,
    file_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Valida, lee, normaliza y exporta un archivo individual."""
    result: dict[str, Any] = {
        "archivo": file_path.name,
        "estado": "error",
        "registros": 0,
    }

    try:
        validated_path = validate_input_path(file_path)
        output_path = output_dir / f"{validated_path.stem}_normalized.csv"

        raw_records = read_file(validated_path)
        valid_records: list[dict[str, Any]] = []

        for line_number, raw_record in enumerate(raw_records, start=1):
            normalized_record = normalize_record(
                raw_record=raw_record,
                logger=logger,
                source_file=validated_path,
                line_number=line_number,
            )

            if normalized_record is not None:
                valid_records.append(normalized_record)

        written_count = write_normalized_csv(valid_records, output_path)

        result["estado"] = "success"
        result["registros"] = written_count
        result["salida"] = str(output_path)

        log_security_event(
            logger=logger,
            event="INGESTION_SUCCESS",
            description="Archivo procesado correctamente.",
            level=logging.INFO,
            archivo=validated_path.name,
            registros=written_count,
            salida=output_path.name,
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

    except Exception as error:
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
# Descubrimiento de archivos
# ---------------------------------------------------------------------------


def discover_input_files(input_dir: Path) -> list[Path]:
    """Encuentra archivos .txt y .csv en el directorio de entrada."""
    if not input_dir.exists():
        raise IngestionError(f"El directorio de entrada no existe: '{input_dir}'.")

    if not input_dir.is_dir():
        raise IngestionError(
            f"La ruta de entrada no es un directorio: '{input_dir}'."
        )

    input_files = [
        candidate
        for candidate in input_dir.iterdir()
        if candidate.is_file()
        and candidate.suffix.lower() in SUPPORTED_EXTENSIONS
    ]

    return sorted(input_files)


# ---------------------------------------------------------------------------
# Interfaz de línea de comandos
# ---------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
    """Define y procesa los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Ingesta segura de archivos TXT y CSV."
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directorio con los archivos de entrada.",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directorio donde se guardarán los archivos normalizados.",
    )

    parser.add_argument(
        "--log-dir",
        type=Path,
        default=DEFAULT_LOG_DIR,
        help="Directorio donde se guardará el log de seguridad.",
    )

    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Detiene la ejecución ante el primer error de seguridad.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Función principal
# ---------------------------------------------------------------------------


def main() -> int:
    """Ejecuta el proceso completo de ingesta."""
    arguments = parse_arguments()

    logger = configure_logging(arguments.log_dir)

    log_security_event(
        logger=logger,
        event="INGESTION_START",
        description="Inicio del proceso de ingesta.",
        level=logging.INFO,
        input_dir=arguments.input_dir,
        output_dir=arguments.output_dir,
    )

    processed_files = 0
    failed_files = 0
    total_records = 0

    try:
        input_files = discover_input_files(arguments.input_dir)
    except IngestionError as error:
        log_security_event(
            logger=logger,
            event="INGESTION_FAILURE",
            description=str(error),
            level=logging.ERROR,
        )
        return 1

    if not input_files:
        log_security_event(
            logger=logger,
            event="NO_INPUT_FILES",
            description="No se encontraron archivos .txt o .csv para procesar.",
            level=logging.WARNING,
            input_dir=arguments.input_dir,
        )
        return 0

    for input_file in input_files:
        file_result = process_file(
            logger=logger,
            file_path=input_file,
            output_dir=arguments.output_dir,
        )

        if file_result["estado"] == "success":
            processed_files += 1
            total_records += file_result["registros"]
        else:
            failed_files += 1

            if arguments.fail_fast:
                log_security_event(
                    logger=logger,
                    event="FAIL_FAST_ACTIVATED",
                    description=(
                        "Ejecución detenida por --fail-fast tras un error."
                    ),
                    level=logging.ERROR,
                    archivo=input_file.name,
                )
                return 1

    log_security_event(
        logger=logger,
        event="INGESTION_SUMMARY",
        description="Resumen final de ingesta.",
        level=logging.INFO,
        archivos_procesados=processed_files,
        archivos_fallidos=failed_files,
        registros_totales=total_records,
    )

    log_security_event(
        logger=logger,
        event="INGESTION_END",
        description="Fin del proceso de ingesta.",
        level=logging.INFO,
    )

    return 0 if failed_files == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
