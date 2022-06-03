from copy import copy
from socket import socket, SOCK_DGRAM, error
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

_all__ = ["Resolver"]


class Resolver:
    def __init__(self, host='localhost', port=53):
        self.host = host
        self.port = port
        self.cached_queries = dict()
        self.root_servers = [
            "198.41.0.4",  # a.root-servers.net
            "199.9.14.201",  # b.root-servers.net
            "192.33.4.12",  # c.root-servers.net
            "199.7.91.13",  # d.root-servers.net
            "192.203.230.10",  # e.root-servers.net
            "192.5.5.241",  # f.root-servers.net
            "192.112.36.4",  # g.root-servers.net
            "198.97.190.53",  # h.root-servers.net
            "192.36.148.17",  # i.root-servers.net
            "192.58.128.30",  # j.root-servers.net
            "193.0.14.129",  # k.root-servers.net
            "199.7.83.42",  # l.root-servers.net
            "202.12.27.33",  # m.root-servers.net
        ]

    def resolve(self, query):
        if query in self.cached_queries:
            return self.cached_queries[query]
        dns_query = dns.message.make_query(qname=query, rdtype=dns.rdatatype.A)
        response = None
        for server in self.root_servers:
            response = self.resolve_recursively(dns_query, server)
            if response:
                self.cached_queries[query] = response
        return response

    def resolve_recursively(self, query, ip):
        response = dns.query.udp(q=query, where=ip)
        if response:
            if response.answer:
                return response
            elif response.additional:
                for additional in response.additional:
                    if additional.rdtype == dns.rdatatype.A:
                        for add_ip in map(str, additional):
                            add_response = self.resolve_recursively(query, add_ip)
                            if add_response:
                                return add_response
        return response

    def run(self):
        sock = socket(type=SOCK_DGRAM)
        try:
            sock.bind((self.host, self.port))
        except error:
            print(f'Unable to bind to ({self.host}, {self.port})')
            exit(1)
        try:
            while True:
                request, _, addr = dns.query.receive_udp(sock)
                for question in map(str, request.question):
                    query = question.split()[0]
                    resolved = self.resolve(dns.name.from_text(query))
                    response = copy(request)
                    response.answer = None
                    response.flags = 0
                    response.flags += dns.flags.RA + dns.flags.QR + dns.flags.RD
                    if resolved:
                        response.answer = resolved.answer
                        if not response.answer:
                            print(f'{query} has no answer section')
                        else:
                            for ans in response.answer:
                                print(ans)
                    dns.query.send_udp(sock, response, addr)
        except KeyboardInterrupt:
            sock.close()
            exit(0)
