"""
Simple persistent-connection test. Starts a coroutine to perform requests over
a single socket, connecting to a server running in the same process.
"""

import asyncio
import logging
import os
import sys
import time

from signal import SIGINT

from icap import run, handler, stop


logging.basicConfig(stream=sys.stderr)


def start_client(pid):
    time.sleep(0.1)

    with open('data/icap_request_with_two_header_sets.request', 'rb') as f:
        sent = f.read()

    loop = asyncio.get_event_loop()

    fastest = 1.0
    slowest = 0.0
    total = 0

    class ICAPClientTestProtocol(asyncio.Protocol):
        def __init__(self, future):
            self.future = future

        def connection_made(self, transport):
            self.transport = transport
            self.count = 0

            self.send_request()

        def send_request(self):
            self.data = b''
            self.count += 1

            self.start = time.time()
            self.transport.write(sent)

        def data_received(self, data):
            nonlocal fastest, slowest

            self.data += data

            if len(self.data) == 314:
                n = time.time() - self.start

                if self.count == per_connection:
                    self.close()
                else:
                    self.send_request()

                fastest = min(fastest, n)
                slowest = max(slowest, n)

        def close(self):
            nonlocal total
            total += self.count
            self.future.set_result("Lamp")
            self.transport.close()

    clients = 100
    per_connection = 10

    s = time.time()

    futures = []

    class ICAPFactory(object):
        def __call__(self):
            nonlocal futures
            future = asyncio.Future()
            futures.append(future)
            return ICAPClientTestProtocol(future)

    try:
        loop.run_until_complete(asyncio.wait([
            loop.create_connection(ICAPFactory(), '127.0.0.1', 1334)
            for i in range(clients)
        ]))

        loop.run_until_complete(asyncio.wait(futures))

        running_time = time.time() - s

        print('%d requests took %f seconds (average=%f, fastest=%f, slowest=%f)'
              % (total, running_time, running_time/total, fastest, slowest))
        assert running_time < 1.01
    finally:
        os.kill(pid, SIGINT)


def main():
    @handler()
    def respmod(request):
        request.body = b'cool woo'

    pid = os.fork()
    if pid == 0:
        e = asyncio.get_event_loop()
        e.add_signal_handler(SIGINT, lambda *args: os._exit(0))
        run(port=1334)
    else:
        start_client(pid)

if __name__ == '__main__':
    main()
