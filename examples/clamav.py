#!/usr/bin/env python
# encoding: utf-8

"""
A very small ICAP server that performs virus scanning on HTTP responses
using ClamAV.

Note that this most certainly needs work if you intend to use it in a
production setting. Ideally it would have;
    - connection pooling for connections to Clam.
    - support for other commands, e.g. ping, file scanning.
    - templating for the virus page (e.g. jinja2)
    - error handling
    - sending the payload in chunks that don't exceed the size of what Clamd expects
    - preview support
"""


import asyncio
import struct

from icap import abort, HTTPResponse, handler, run

loop = asyncio.get_event_loop()


class ClamAVProtocol(asyncio.Protocol):
    def __init__(self, future, payload):
        self.future = future
        self.payload = payload
        self.response_data = b''

    def connection_made(self, transport):
        self.transport = transport

        self.transport.write(b'nINSTREAM\n')

        size = struct.pack(b'!L', len(self.payload))
        self.transport.write(size + self.payload)
        self.transport.write(struct.pack(b'!L', 0))

    def data_received(self, data):
        self.response_data += data

        if b'\n' not in self.response_data:
            return

        self.transport.close()

        response = self.response_data.split(b'\n')[0]

        if response.endswith(b'FOUND'):
            name = response.split(b':', 1)[1].strip()
            self.future.set_result((True, name))
        else:
            self.future.set_result((False, None))


def clamav_scan(payload):
    future = asyncio.Future()
    if payload:
        scanner = ClamAVProtocol(future, payload)
        asyncio.async(loop.create_connection(lambda: scanner, host='127.0.0.1', port=3310))
    else:
        future.set_result((False, None))
    return future


@handler()
def respmod(request):
    found_virus, name = yield from clamav_scan(request.body_bytes)

    if found_virus:
        return HTTPResponse(body=b"A virus was found: " + name)
    else:
        abort(204)


if __name__ == '__main__':
    run()
