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

from icap import run, handler


logging.basicConfig(stream=sys.stderr)


def start_client(pid):
    time.sleep(0.1)

    with open('data/icap_request_with_two_header_sets.request', 'rb') as f:
        sent = f.read()

    loop = asyncio.get_event_loop()

    COUNT = 10

    class ICAPClientTestProtocol(asyncio.Protocol):
        def connection_made(self, transport):
            self.transport = transport
            self.count = 0

            self.fastest = 1.0
            self.slowest = 0.0
            self.total = 0.0

            self.send_request()

        def send_request(self):
            self.data = b''
            self.count += 1

            self.start = time.time()
            self.transport.write(sent)

        def data_received(self, data):
            self.data += data

            if len(self.data) == 314:
                n = time.time() - self.start
                print('client %.5f' % n)

                if self.count == COUNT:
                    self.transport.close()
                    loop.stop()
                    print(
                        '%d requests took %f seconds (average=%f, fastest=%f, slowest=%f)'
                            % (COUNT, self.total, (self.total/COUNT),
                               self.fastest, self.slowest))
                else:
                    self.send_request()

                self.fastest = min(self.fastest, n)
                self.slowest = max(self.slowest, n)
                self.total += n

    f = loop.create_connection(ICAPClientTestProtocol, '127.0.0.1', 1334)
    loop.run_until_complete(f)
    loop.run_forever()
    os.kill(pid, SIGINT)


def main():
    @handler(lambda *args: True)
    def respmod(request):
        request.body = b'cool woo'

    pid = os.fork()
    if pid == 0:
        run(port=1334)
    else:
        start_client(pid)

if __name__ == '__main__':
    main()
