import base64
import json
import logging
import zlib
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any
from threading import Timer

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy import types
from mitmproxy import version
from mitmproxy.connection import Server
from mitmproxy.coretypes.multidict import _MultiDict
from mitmproxy.log import ALERT
from mitmproxy.utils import human
from mitmproxy.utils import strutils

logger = logging.getLogger(__name__)


class HARDUMPER:
    def __init__(self) -> None:
        self.flows: list[flow.Flow] = []  # List to collect flows
        self.filt: flowfilter.TFilter | None = None
        self.dump_interval_seconds = 10  # Set interval to 10 seconds (for testing purposes)
        self.schedule_har_dump()

    def schedule_har_dump(self):
        """Schedule the HAR dump every interval"""
        Timer(self.dump_interval_seconds, self.dump_har_periodically).start()

    def dump_har_periodically(self):
        """Method to dump the HAR file every interval with a timestamp in the filename"""
        if self.flows:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"har_dump_{timestamp}.har"
            logging.log(ALERT, f"Creating HAR file: {filename}")
            self.export_har(self.flows, f"/home/mitmproxy/.mitmproxy/{filename}")
            logging.log(ALERT, f"HAR file saved: {filename} ({len(self.flows)} flows)")
            self.flows.clear()  # Clear the internal flows list after saving
            ctx.master.commands.call("view.clear")  # Clear flows in mitmproxy's view

        # Re-schedule for the next interval
        self.schedule_har_dump()

    @command.command("save.har")
    def export_har(self, flows: Sequence[flow.Flow], path: types.Path) -> None:
        """Export flows to a HAR (HTTP Archive) file."""
        har = json.dumps(self.make_har(flows), indent=4).encode()

        if path.endswith(".zhar"):
            har = zlib.compress(har, 9)

        with open(path, "wb") as f:
            f.write(har)

        logging.log(ALERT, f"HAR file saved ({human.pretty_size(len(har))} bytes).")

    def make_har(self, flows: Sequence[flow.Flow]) -> dict:
        entries = []
        skipped = 0
        servers_seen: set[Server] = set()

        for f in flows:
            if isinstance(f, http.HTTPFlow):
                entries.append(self.flow_entry(f, servers_seen))
            else:
                skipped += 1

        if skipped > 0:
            logger.info(f"Skipped {skipped} flows that weren't HTTP flows.")

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "mitmproxy",
                    "version": version.VERSION,
                    "comment": "",
                },
                "pages": [],
                "entries": entries,
            }
        }

    def response(self, flow: http.HTTPFlow) -> None:
        logger.info(f"Processing HTTP response: {flow.request.url}")
        if flow.websocket is None:
            self._save_flow(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        logger.error(f"Error occurred in flow: {flow.error}")
        self.response(flow)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self._save_flow(flow)

    def _save_flow(self, flow: http.HTTPFlow) -> None:
        # Removed dependency on ctx.options.hardump
        flow_matches = self.filt is None or self.filt(flow)
        if flow_matches:
            logger.info(f"Saving flow: {flow.request.url}")
            self.flows.append(flow)
        else:
            logger.info(f"Flow does not match filter: {flow.request.url}")

    def flow_entry(self, flow: http.HTTPFlow, servers_seen: set[Server]) -> dict:
        """Creates HAR entry from flow"""

        if flow.server_conn in servers_seen:
            connect_time = -1.0
            ssl_time = -1.0
        elif flow.server_conn.timestamp_tcp_setup:
            assert flow.server_conn.timestamp_start
            connect_time = 1000 * (
                flow.server_conn.timestamp_tcp_setup - flow.server_conn.timestamp_start
            )

            if flow.server_conn.timestamp_tls_setup:
                ssl_time = 1000 * (
                    flow.server_conn.timestamp_tls_setup
                    - flow.server_conn.timestamp_tcp_setup
                )
            else:
                ssl_time = -1.0
            servers_seen.add(flow.server_conn)
        else:
            connect_time = -1.0
            ssl_time = -1.0

        if flow.request.timestamp_end:
            send = 1000 * (flow.request.timestamp_end - flow.request.timestamp_start)
        else:
            send = 0

        if flow.response and flow.request.timestamp_end:
            wait = 1000 * (flow.response.timestamp_start - flow.request.timestamp_end)
        else:
            wait = 0

        if flow.response and flow.response.timestamp_end:
            receive = 1000 * (
                flow.response.timestamp_end - flow.response.timestamp_start
            )
        else:
            receive = 0

        timings: dict[str, float | None] = {
            "connect": connect_time,
            "ssl": ssl_time,
            "send": send,
            "receive": receive,
            "wait": wait,
        }

        if flow.response:
            response_body_size = (
                len(flow.response.raw_content) if flow.response.raw_content else 0
            )
            response_body_decoded_size = (
                len(flow.response.content) if flow.response.content else 0
            )
            response_body_compression = response_body_decoded_size - response_body_size
            response = {
                "status": flow.response.status_code,
                "statusText": flow.response.reason,
                "httpVersion": flow.response.http_version,
                "cookies": self.format_response_cookies(flow.response),
                "headers": self.format_multidict(flow.response.headers),
                "content": {
                    "size": response_body_size,
                    "compression": response_body_compression,
                    "mimeType": flow.response.headers.get("Content-Type", ""),
                },
                "redirectURL": flow.response.headers.get("Location", ""),
                "headersSize": len(str(flow.response.headers)),
                "bodySize": response_body_size,
            }
            if flow.response.content and strutils.is_mostly_bin(flow.response.content):
                response["content"]["text"] = base64.b64encode(
                    flow.response.content
                ).decode()
                response["content"]["encoding"] = "base64"
            else:
                text_content = flow.response.get_text(strict=False)
                if text_content is None:
                    response["content"]["text"] = ""
                else:
                    response["content"]["text"] = text_content
        else:
            response = {
                "status": 0,
                "statusText": "",
                "httpVersion": "",
                "headers": [],
                "cookies": [],
                "content": {},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
                "_transferSize": 0,
                "_error": None,
            }
            if flow.error:
                response["_error"] = flow.error.msg

        if flow.request.method == "CONNECT":
            url = f"https://{flow.request.pretty_url}/"
        else:
            url = flow.request.pretty_url

        entry: dict[str, Any] = {
            "startedDateTime": datetime.fromtimestamp(
                flow.request.timestamp_start, timezone.utc
            ).isoformat(),
            "time": sum(v for v in timings.values() if v is not None and v >= 0),
            "request": {
                "method": flow.request.method,
                "url": url,
                "httpVersion": flow.request.http_version,
                "cookies": self.format_multidict(flow.request.cookies),
                "headers": self.format_multidict(flow.request.headers),
                "queryString": self.format_multidict(flow.request.query),
                "headersSize": len(str(flow.request.headers)),
                "bodySize": len(flow.request.content) if flow.request.content else 0,
            },
            "response": response,
            "cache": {},
            "timings": timings,
        }

        if flow.request.method in ["POST", "PUT", "PATCH"]:
            params = self.format_multidict(flow.request.urlencoded_form)
            entry["request"]["postData"] = {
                "mimeType": flow.request.headers.get("Content-Type", ""),
                "text": flow.request.get_text(strict=False),
                "params": params,
            }

        if flow.server_conn.peername:
            entry["serverIPAddress"] = str(flow.server_conn.peername[0])

        websocket_messages = []
        if flow.websocket:
            for message in flow.websocket.messages:
                if message.is_text:
                    data = message.text
                else:
                    data = base64.b64encode(message.content).decode()
                websocket_message = {
                    "type": "send" if message.from_client else "receive",
                    "time": message.timestamp,
                    "opcode": message.type.value,
                    "data": data,
                }
                websocket_messages.append(websocket_message)

            entry["_resourceType"] = "websocket"
            entry["_webSocketMessages"] = websocket_messages
        return entry

    def format_response_cookies(self, response: http.Response) -> list[dict]:
        cookie_list = response.cookies.items(multi=True)
        rv = []
        for name, (value, attrs) in cookie_list:
            cookie = {
                "name": name,
                "value": value,
                "path": attrs.get("path", "/"),
                "domain": attrs.get("domain", ""),
                "httpOnly": "httpOnly" in attrs,
                "secure": "secure" in attrs,
            }
            if "sameSite" in attrs:
                cookie["sameSite"] = attrs["sameSite"]
            rv.append(cookie)
        return rv

    def format_multidict(self, obj: _MultiDict[str, str]) -> list[dict]:
        return [{"name": k, "value": v} for k, v in obj.items(multi=True)]


addons = [HARDUMPER()]
