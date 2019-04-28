import socket
from datetime import datetime, timedelta
from dns_parser import DnsParser


class ResourceRecord:
    def __init__(self, record):
        self.name = record.name
        self.rtype = record.rtype
        self.rclass = record.rclass
        ttl = int.from_bytes(record.ttl, byteorder='big')
        self.cached_until = datetime.now() + timedelta(seconds=ttl)
        self.rdlength = record.rdlength
        self.rdata = record.rdata

    def to_dns_format(self):
        return self.name + \
               self.rtype + \
               self.rclass + \
               int.to_bytes(0, 4, byteorder='big', signed=False) + \
               self.rdlength + self.rdata


class DnsServer:
    def __init__(self, server_address, forwarder_address):
        self.forwarder_address = forwarder_address
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.forwarder_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.bind(('127.0.0.1', 53))
        self.forwarder_sock.connect(forwarder_address)
        self.cache = dict()

    def make_response_from_cache(self, id, name, qtype, query):
        if name in self.cache and qtype in self.cache[name]:
            for record in self.cache[name][qtype]:
                if datetime.now() >= record.cached_until:
                    print('remove')
                    self.cache[name][qtype].remove(record)
            if len(self.cache[name][qtype]) > 0:
                record = self.cache[name][qtype][0]
            else:
                return False
        else:
            return False
        response = b''
        response += id + b'\x80\x00' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + query[2:] + record.to_dns_format()
        return response

    def start(self):
        while True:
            query, addr = self.server_sock.recvfrom(1024)
            parsed_query = DnsParser.parse_query(query)
            response = self.make_response_from_cache(parsed_query.id, parsed_query.qname, parsed_query.qtype, query)
            if response:
                self.server_sock.sendto(response, addr)
            else:
                self.forwarder_sock.sendto(query, self.forwarder_address)
                response, _ = self.forwarder_sock.recvfrom(4096)
                self.server_sock.sendto(response, addr)
                records = DnsParser.parse_response(response)
                if records:
                    for record in records:
                        record = ResourceRecord(record)
                        if record.name not in self.cache:
                            self.cache[record.name] = dict()
                        if record.rtype not in self.cache[record.name]:
                            self.cache[record.name][record.rtype] = list()
                        self.cache[record.name][record.rtype].append(record)


def main():
    server = DnsServer(('127.0.0.1', 53), ('212.193.163.7', 53))
    server.start()


if __name__ == '__main__':
    main()

