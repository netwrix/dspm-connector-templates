#!/usr/bin/env python
import base64
import json
import logging
import os
from datetime import UTC, datetime
from logging.config import dictConfig

import requests
from flask import Flask, jsonify, request
from waitress import serve

from function import handler

logger = logging.getLogger(__name__)


dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
            }
        },
        "root": {"level": os.getenv("LOG_LEVEL", "INFO").upper(), "handlers": ["wsgi"]},
    }
)


app = Flask(__name__)

class Event:
    def __init__(self):
        self.body = request.get_data()
        self.headers = request.headers
        self.method = request.method
        self.query = request.args
        self.path = request.path

class Context:
    def __init__(self):
        pass


def format_status_code(resp):
    return resp.get("statusCode", 200)


def format_body(resp):
    body = resp.get("body", "")
    if isinstance(body, dict):
        return jsonify(body)
    return str(body)


def format_headers(resp):
    headers = resp.get("headers", [])
    if isinstance(headers, dict):
        return [(key, value) for key, value in headers.items()]
    return headers


def format_response(resp):
    if resp is None:
        return ("", 200)
    if isinstance(resp, dict):
        return (format_body(resp), format_status_code(resp), format_headers(resp))
    return resp


@app.route('/', defaults={'path': ''}, methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
def call_handler(path):
    event = Event()
    context = Context()
    response_data = handler.handle(event, context)

    return format_response(response_data)

if __name__ == "__main__":
    is_debug = os.getenv("DEBUG_MODE", "false").lower() == "true"
    debug_library = os.getenv("DEBUG_LIBRARY", "debugpy").lower()
    debug_host = os.getenv("DEBUG_HOST", "0.0.0.0")
    debug_port = int(os.getenv("DEBUG_PORT", 5678))

    if is_debug:
        try:
            if debug_library == "debugpy":
                import debugpy # type: ignore # noqa

                debugpy.listen((debug_host, debug_port)) # type: ignore # noqa
            elif debug_library == "pycharm":
                import pydevd_pycharm # type: ignore # noqa

                pydevd_pycharm.settrace(debug_host, port=debug_port, stdoutToServer=True, stderrToServer=True)
            else:
                app.logger.error(f"Unknown debug library: {debug_library}. Supported: debugpy, pycharm.")
        except Exception as e:
            app.logger.error(
                f"Connection to debugger failed: {str(e)}. Ensure your debugger is configured correctly or set DEBUG_MODE to false."
            )

        logger.debug(f"Using {debug_library} debugger on {debug_host}:{debug_port}.")
        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=False)
    else:
        serve(app, host="0.0.0.0", port=5000)
