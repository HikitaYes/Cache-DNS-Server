import socket, time

class DNSserver:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(2)
        self.s.bind(('127.0.0.1', 53))
        self.cache = dict()
        self.initCache()

    def loop(self):
        try:
            while True:
                try:
                    query, addr = self.s.recvfrom(512)
                except socket.timeout:
                    continue
                else:
                    name, qType, nextByte = self.parseQuestion(query[12:])
                    if qType == b'\x00\x0c' and name == b'\x011\x010\x010\x03127\x07in-addr\x04arpa\x00': # PTR запись и my host
                        flags = (query[2] + 128).to_bytes(1, 'big') + b'\x83' # флаг error: No such name
                        self.s.sendto(query[0:2] + flags + query[4:], addr)
                        continue
                    if (name, qType) in self.cache:
                        response = self.buildResponse(query, name, qType)
                        self.s.sendto(response, addr)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(query, ('8.8.8.8', 53))
                        responseDNS, addrDNS = sock.recvfrom(512)
                        if responseDNS != None:
                            self.s.sendto(responseDNS, addr)
                            result, TTL = self.parseResponse(responseDNS, nextByte)
                            if result != []:
                                self.cache[(name, qType)] = (result, TTL, time.time())
                        else:
                            flags = (query[2] + 128).to_bytes(1, 'big') + b'\x82' # Server Failure
                            responseError = query[0:2] + flags + query[4:]
                            self.s.sendto(responseError, addr)
                    self.checkCacheTTL()
        except KeyboardInterrupt:
            self.saveCache()

    def parseQuestion(self, data):
        name = b''
        i = 0
        while data[i] != 0:
            expectedLength = data[i]
            name += data[i: i + 1 + expectedLength]
            i += expectedLength + 1
        else:
            name += data[i: i + 1]
            qType = data[i + 1: i + 3]
            nextByte = i + 5
        return (name, qType, nextByte)

    def parseResponse(self, data, nextByte):
        countAnswers = data[6:8]
        countAAsnwers = data[8:10]
        countAdditional = data[10:12]
        nextByte += 12
        result = []
        nextByte += 6 # skip name, type, class
        TTL = data[nextByte: nextByte + 4]
        nextByte += 4

        for i in range(countAnswers[1]):
            if i != 0:
                nextByte += 10 # skip name link, type, class, TTL
            length = int.from_bytes(data[nextByte : nextByte + 2], 'big')
            nextByte += 2
            info = data[nextByte : nextByte + length]
            nextByte += length
            result.append(info)

        for i in range(countAAsnwers[1]):
            if i != 0:
                nextByte += 10 # skip name, type, class, TTL
            length = int.from_bytes(data[nextByte : nextByte + 2], 'big')
            nextByte += 2
            info = data[nextByte : nextByte + length]
            nextByte += length
            result.append(info)

        for i in range(countAdditional[1]):
            if i != 0:
                nextByte += 10 # skip name, type, class, TTL
            length = int.from_bytes(data[nextByte: nextByte + 2], 'big')
            nextByte += 2
            info = data[nextByte: nextByte + length]
            nextByte += length
            result.append(info)

        return result, TTL

    def buildResponse(self, data, name, qType):
        (results, TTL, _) = self.cache[(name, qType)]
        transactionID = data[0:2]
        flags = self.getFlags(data[2:4])
        QDCOUNT = b'\x00\x01'
        ANCOUNT = len(results).to_bytes(2, 'big')
        NSCOUNT = b'\x00\x00'
        ARCOUNT = b'\x00\x00'
        Query = data[12:]
        Answer = b''
        for result in results:
            Answer += name + qType + b'\x00\x01' + TTL + len(result).to_bytes(2, 'big') + result
        return transactionID + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT + Query + Answer

    def getFlags(self, flags):
        byte1 = bytes(flags[: 1])
        QR = '1'
        OPCODE = ''
        for bit in range(1, 5):
            OPCODE += str(ord(byte1) & (1 << bit))
        AA = '0'
        TC = '0'
        RD = '1'
        RA = '1'
        Z = '000'
        RCODE = '0000'
        return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, 'big') + int(RA + Z + RCODE, 2).to_bytes(1, 'big')

    def checkCacheTTL(self):
        keysToDel = []
        for key, value in self.cache.items():
            if int.from_bytes(value[1], 'big') + value[2] <= time.time():
                keysToDel.append(key)
        for key in keysToDel:
            del self.cache[key]

    def initCache(self):
        info = b''
        try:
            with open('cache.txt', 'rb') as f:
                for line in f:
                    info += line # чтобы собрать байт с "переносом строки" \n
        except IOError as e:
            print(e)
        self.parseDataCache(info)
        self.checkCacheTTL()

    def saveCache(self):
        f = open('cache.txt', 'wb')
        for key, value in self.cache.items():
            f.write(key[0] + b'ff' + key[1] + b'ff')
            for result in value[0]:
                f.write(result + b'ff')
            f.write(value[1] + b'ff' + int(value[2]).to_bytes(5, 'big') + b'xx')
        f.close()

    def parseDataCache(self, data):
        records = data.split(b'xx')[0:-1]
        for record in records:
            parts = record.split(b'ff')
            key = (parts[0], parts[1])
            time = int.from_bytes(parts[-1], 'big')
            TTL = parts[-2]
            results = []
            for i in range(2, len(parts) - 2):
                results.append(parts[i])
            value = (results, TTL, time)
            self.cache[key] = value


if __name__ == '__main__':
    dns = DNSserver()
    dns.loop()