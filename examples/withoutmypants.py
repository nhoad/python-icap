#!/usr/bin/env python3

from icap import DomainCriteria, handler, run


@handler(DomainCriteria('*google.*'))
def reqmod(request):
    query = request.request_line.query

    if 'q' in query:
        request.request_line.query['q'][0] += ' without my pants'


if __name__ == '__main__':
    run(host='127.0.0.1', port=1334)
