"""
Simple persistent-connection test. Starts a coroutine to perform requests over
a single socket, connecting to a server running in the same process.
"""

from gevent import monkey, spawn_later, with_timeout
monkey.patch_all()

import logging
import os
import socket
import sys
import time

from gevent.server import StreamServer

from icap import Server


logging.basicConfig(stream=sys.stderr)


def start_client(server):
    def later():
        s = socket.socket()
        s.connect(('127.0.0.1', 1334))

        with open('data/icap_request_with_two_header_sets.request') as f:
            sent = f.read()

        fastest = 1.0
        slowest = 0.0
        total = 0.0
        try:
            for i in range(1, 1301):
                start = time.time()
                s.sendall(sent)
                received = ''

                # context switches mean premature reads sometimes. It's bad, I know.
                # Would be fixed by separate processes for client/server.
                while len(received) != 314:
                    received += s.recv(314)

                n = time.time() - start

                fastest = min(fastest, n)
                slowest = max(slowest, n)

                total += n

                print n, 'sent=%d' % len(sent), 'recv=%d' % len(received)

                try:
                    assert received.endswith('cool woo\r\n0\r\n\r\n')
                except Exception:
                    print 'Unexpected error!', i
                    print repr(received)
                    print '=' * 50
                    print 'sent'
                    print '=' * 50
                    print sent
                    print '=' * 50
                    print 'received'
                    print '=' * 50
                    # return code for Makefile
                    os._exit(1)
        finally:
            print '%d requests took %f seconds (average=%f, fastest=%f, slowest=%f)' % (i, total, (total/i), fastest, slowest)
            print 'closing'
            s.close()
            server.stop()

    spawn_later(1, with_timeout, 1, later)


def main():
    server = Server(StreamServer)

    @server.handler(lambda *args: True)
    def respmod(request):
        request.body = 'cool woo'

    start_client(server)
    server.run()

if __name__ == '__main__':
    main()
