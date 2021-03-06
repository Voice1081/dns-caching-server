from collections import namedtuple

dns_query = namedtuple('dns_query', ['query', 'id', 'qname', 'qtype'])
dns_resource_record = namedtuple('dns_resource_record', ['authoritative', 'name', 'rtype', 'rclass', 'ttl', 'rdlength', 'rdata'])


class DnsParser:
    @staticmethod
    def get_offset(two_bytes):
        bits = to_bits(two_bytes)
        if bits[:2] == '11':
            offset = int(bits[2:], 2)
            return offset
        return 0

    @staticmethod
    def parse_query(query):
        id = query[0:2]
        qsection = query[12:]
        pos = 0
        while qsection[pos] != 0:
            pos += 1
        qname = qsection[:pos+1]
        qtype = qsection[pos+1:pos+3]
        return dns_query(query, id, qname, qtype)

    @staticmethod
    def parse_response(response):
        records = list()
        authoritative = int(to_bits(response[2:4])[0])
        rcode = int(to_bits(response[2:4])[1:5], 2)
        if rcode != 0:
            return None
        questions = int(to_bits(response[4:6]), 2)
        answers = int(to_bits(response[6:8]), 2)
        authority = int(to_bits(response[8:10]), 2)
        additional = int(to_bits(response[10:12]), 2)
        offset = 12
        for i in range(0, questions):
            _, offset = DnsParser.get_name(response, offset)
            offset += 4
        for i in range(0, answers + authority + additional):
            record, offset = DnsParser.parse_resource_record(response, offset, authoritative)
            records.append(record)
        return records

    @staticmethod
    def parse_resource_record(response, offset, authoritative):
        name, offset = DnsParser.get_name(response, offset)
        rtype = response[offset:offset+2]
        rclass = response[offset+2:offset+4]
        ttl = response[offset+4:offset+8]
        rdlength = response[offset+8:offset+10]
        length = int.from_bytes(rdlength, byteorder='big')
        rdata = response[offset+10:offset+10+length]
        offset += 10 + length
        return dns_resource_record(authoritative, name, rtype, rclass, ttl, rdlength, rdata), offset

    @staticmethod
    def get_name(response, offset):
        name = b''
        while offset < len(response) and response[offset] != 0:
            pointer_offset = DnsParser.get_offset(response[offset:offset+2])
            if pointer_offset:
                part, _ = DnsParser.get_name(response, pointer_offset)
                name += part
                offset += 2
                return name, offset
            else:
                length = response[offset]
                name += response[offset:offset + length + 1]
                offset += length + 1
        name += b'\x00'
        return name, offset + 1

    @staticmethod
    def get_part_by_offset(response, offset):
        # part = b''
        # while offset < len(response) and response[offset] != 0:
        #     length = response[offset]
        #     part += response[offset:offset+length+1]
        #     offset += length + 1
        length = response[offset]
        part = response[offset:offset+length+1]
        return part


def to_bits(bytestr):
    bits = ''
    for byte in bytestr:
        bits += bin(byte)[2:].zfill(8)
    return bits


def main():
    packet = b'\x00\x15\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02e1\x02ru\x00\x00\x01\x00\x01\x02e1\x02ru\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xd4\xc1\xa3\x06'
    records = DnsParser.parse_response(packet)
    for record in records:
        print(record.name)


if __name__ == '__main__':
    main()
