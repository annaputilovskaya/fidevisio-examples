"""Пример приёмника webhook-алертов FideVisio с проверкой подписи.

Запуск:

    FIDEVISIO_WEBHOOK_SECRET=<секрет канала> python receiver_python.py

Секрет — значение `webhook_secret` канала в настройках FideVisio. Подпись
считается как HMAC-SHA256 от сырых байт тела запроса, заголовок `X-Signature`
имеет вид `sha256=<hex>`.

Зависимостей нет — только стандартная библиотека.
"""

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

SECRET: bytes = os.environ["FIDEVISIO_WEBHOOK_SECRET"].encode()
HOST = "0.0.0.0"
PORT = 8080


def signature_matches(raw: bytes, header: str) -> bool:
    """Проверяет подпись `X-Signature` по сырым байтам тела.

    Args:
        raw: сырые байты тела запроса.
        header: значение заголовка X-Signature.

    Returns:
        True, если подпись совпадает.
    """
    expected = "sha256=" + hmac.new(SECRET, raw, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def handle_event(event: dict[str, Any]) -> None:
    """Обрабатывает событие алерта (пример: печать в stdout).

    Args:
        event: объект `event` из тела запроса.
    """
    detail = event.get("error_detail") or "ok"
    print(f"{event['event_type']}: {event['monitor_name']} — {detail}")


class Handler(BaseHTTPRequestHandler):
    """HTTP-обработчик, принимающий POST от FideVisio."""

    def do_POST(self) -> None:  # noqa: N802 (имя задано stdlib)
        """Читает тело, проверяет подпись и обрабатывает событие."""
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not signature_matches(raw, self.headers.get("X-Signature", "")):
            self.send_response(401)
            self.end_headers()
            return
        payload = json.loads(raw)
        handle_event(payload["event"])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        """Подавляет стандартный HTTP-лог (демонстрационный пример)."""
        return


if __name__ == "__main__":
    print(f"listening on http://{HOST}:{PORT}")
    HTTPServer((HOST, PORT), Handler).serve_forever()
