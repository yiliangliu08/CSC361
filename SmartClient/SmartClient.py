"""
Name: Yiliang Liu
StudentID: V00869672
"""

import sys
import ssl
import socket
from urllib.parse import urlparse


class SmartClient:
    def __init__(self, url):
        self.count = 0
        self.sock = None
        self.protocol = None
        self.cookies = []
        # Formatting the address
        self.url = urlparse("https://{}".format(url))
        https = self.use_https()
        http = False
        https2 = False
        # Assume that if https is not supported, http2 will also not be supported
        if https is False:
            http = self.use_http()
        else:
            https2 = self.use_http2(https)
        if self.sock is not None:
            self.sock.close()
        print('website: ' + url)
        print('1. Supports of HTTPS: ' + str(https))
        if http is True or https is True:
            print('2. Supports http1.1: True')
        else:
            print('2. Supports http1.1: False')
        print('3. Supports http2: ' + str(https2))
        print('4. List of Cookies: ')
        for cookie in self.cookies:
            cookie_name = cookie['cookie name']
            expire_time = (', expire time: ' + cookie['expire time']) if cookie['expire time'] is not None else ''
            domain = (', domain: ' + cookie['domain']) if cookie['domain'] is not None else ''
            output = 'cookie name: ' + cookie_name + expire_time + domain
            print(output)

    # Check if https is supported
    def use_https(self):
        result = self.open_socket(self.url)
        # Automatically return false, if socket fail to connect
        if result is False:
            return False
        # Send and receive
        self.generate_request('GET', self.url, 'HTTP/1.1')
        header, status = self.receive()
        header_lines = header.split('\r\n')
        # If it's 200, connection is success. In case of 403, the connection is success, but permission denied
        if '200' not in status and self.count == 0:
            if '403' in status:
                return True
            for header_line in header_lines:
                # In case of 302/301, check if redirect is needed.
                if 'location' in header_line.lower():
                    redirect = header_line.split(' ')
                    self.url = urlparse(redirect[1])
                    self.count = 1
                    self.sock.close()
                    if self.use_https() is True:
                        return True
                    else:
                        return False
            return False
        return True

    # check if connection can be established through http
    def use_http(self):
        self.sock.close()
        result = self.open_socket(self.url, False)
        if result is False:
            return False
        self.generate_request('GET', self.url, 'HTTP/1.1', True)
        header, status = self.receive()
        header_lines = header.split('\r\n')
        # if '200' not in status:
        #     if 'HTTP/1.1' in status:
        #         return True
        #     return False
        # return True
        if ('200' or '403') not in status and self.count == 0:
            for header_line in header_lines:
                if 'location' in header_line.lower():
                    redirect = header_line.split(' ')
                    self.url = urlparse(redirect[1])
                    self.count = 1
                    self.sock.close()
                    if self.use_http() is True:
                        return True
                    else:
                        return False
            return False
        return True

    # check if http2 is supported by checking the protocol
    def use_http2(self, https):
        self.sock.close()
        try:
            if https is True:
                result = self.open_socket(self.url, True, True)
                if result is False:
                    return False
                if self.sock.selected_alpn_protocol() == 'h2':
                    return True
        except (socket.error, ssl.CertificateError, ssl.SSLError, socket.timeout):
            return False
        return False

    # Open socket, https will be True as default.
    def open_socket(self, url, https=True, h2=False):
        if https is True:
            port = 443
        else:
            port = 80
        if h2 is True:
            protocol = ['h2', 'http/1.1', 'http/1.0']
        else:
            protocol = ['http/1.1', 'http/1.0']
        try:
            ip_address = socket.gethostbyname(url.netloc)
        except socket.gaierror:
            print("Something is wrong with the input address")
            exit()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if https is True:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(protocol)
            ssl_sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=url.netloc)
            self.sock = ssl_sock
        try:
            self.sock.settimeout(4)
            self.sock.connect((ip_address, port))
            self.sock.settimeout(None)
        except (socket.error, ssl.CertificateError, ssl.SSLError, socket.timeout):
            return False
        return True

    # Create request for http and https.
    def generate_request(self, method, url, http_version, upgrade=False):
        if url.path == '':
            path = '/'
        else:
            path = url.path
        if upgrade is False:
            request = method + ' ' + path + ' ' + http_version \
                      + "\r\nHost: " + url.netloc \
                      + "\r\nconnection: " + "keep-alive""\r\n\r\n"
        else:
            upgrade_field = 'Connection: close\r\nUpgrade: h2c\r\n\r\n'
            request = 'GET ' + path + ' ' + http_version + "\r\nHost: " + url.netloc + '\r\n' + upgrade_field
        print('---Request begin---')
        print(request)
        # self.sock.send(request.encode())
        self.sock.send(request.encode())
        print('---Request end---')
        print('HTTP request sent, awaiting response...')

    # Handle the response and extract cookie that's being used
    def receive(self):
        # print(self.sock.recv(1024))
        response = self.sock.recv(1024).decode(errors='ignore')
        print('\n---Respond header---')
        split_response = response.split("\r\n\r\n")
        header = split_response[0]
        print(header)
        header_lines = header.split('\r\n')
        if len(self.cookies) != 0:
            self.cookies = []
        for header_line in header_lines[1:]:
            attribute = header_line.split(': ')
            if attribute[0].lower() == 'set-cookie':
                chips = attribute[1].split('; ')
                name = chips[0].split('=')
                cookie_name = name[0]
                domain = None
                expire = None
                for chip in chips:
                    if 'expire' in chip.lower():
                        expire = chip.split('=')[1]
                    if 'domain' in chip.lower():
                        domain = chip.split('=')[1]
                cookie = {
                    'cookie name': cookie_name,
                    'expire time': expire,
                    'domain': domain
                }
                self.cookies.append(cookie)
        try:
            if len(split_response[1]) is not None:
                print('\n---Response Body---')
                print(split_response[1])
        except IndexError:
            print('\n---Response Body---')
        return header, header_lines[0]


if __name__ == "__main__":
    SmartClient(sys.argv[1])
