#!/usr/bin/env python3
"""Minimal stdio MCP fixture; never connects to a network or uses credentials."""
import json
import pathlib
import socket
import sys


for line in sys.stdin:
    request = {}
    try:
        request = json.loads(line)
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": request.get("params", {}).get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}}, "serverInfo": {"name": "native-write-probe", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "write_sample", "description": "Write a test marker", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}]}
        elif method == "tools/call":
            if request["params"]["name"] == "inspect_boundary":
                checks = {}
                try:
                    pathlib.Path(request["params"]["arguments"]["path"]).read_text(encoding="utf8")
                    checks["outside_read_denied"] = False
                except PermissionError:
                    checks["outside_read_denied"] = True
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    checks["udp_socket_denied"] = False
                except PermissionError:
                    checks["udp_socket_denied"] = True
                result = {"content": [{"type": "text", "text": json.dumps(checks)}]}
                print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
                continue
            target = pathlib.Path(request["params"]["arguments"]["path"])
            try:
                target.write_text("mcp", encoding="utf8")
                result = {"content": [{"type": "text", "text": "written"}]}
            except OSError as error:
                result = {"content": [{"type": "text", "text": f"denied:{error.errno}"}], "isError": True}
        else:
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
    except Exception as error:
        print(json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32000, "message": str(error)}}), flush=True)
