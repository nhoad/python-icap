#!/usr/bin/env python2.7

from icap import Server, DomainCriteria

server = Server()


@server.handler(DomainCriteria('*google.*'))
def reqmod(request):
    query = request.request_line.query

    if 'q' in query:
        request.request_line.query['q'][0] += ' without my pants'


if __name__ == '__main__':
    server.run()
