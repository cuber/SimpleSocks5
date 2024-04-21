#!/usr/bin/env python3

import asyncio
import socket
import struct

__version__ = '1.0.4'
__author__ = 'spcharc'

class IncorrectFormat(Exception):
    pass

class SocksVersionIncorrect(Exception):
    pass

class AuthMethodNotSupported(Exception):
    pass

class UnsupportedCommand(Exception):
    pass

class AddressTypeNotSupported(Exception):
    pass

class HostNotFound(Exception):
    pass

class ConnectionRefused(Exception):
    pass

class ConnectionFailed(Exception):
    pass

async def pipe_data(reader, writer):
    try:
        while True:
            data = await reader.read(8192)  # 8kb
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()

async def read_struct(reader, data_format):
    length = struct.calcsize(data_format)
    content = await reader.readexactly(length)
    return struct.unpack(data_format, content)

async def socks4_handler(reader, writer, header):
    try:
        cmd, dstport, dstip = struct.unpack('!BH4s', header[1:8])
        user_id = []
        while True:
            byte = await reader.readexactly(1)
            if byte == b'\x00':
                break
            user_id.append(byte)
        user_id = b''.join(user_id).decode()

        dstip_str = socket.inet_ntoa(dstip)
        if cmd != 1:  # 1=connect
            writer.write(struct.pack('!BBH4s', 0, 91, 0, b'\x00\x00\x00\x00'))  # request rejected or failed
            await writer.drain()
            return

        print(f'SOCKS4 connect to {dstip_str}:{dstport}')
        remote_reader, remote_writer = await asyncio.open_connection(dstip_str, dstport)
        writer.write(struct.pack('!BBH4s', 0, 90, dstport, dstip))  # request granted
        await writer.drain()

        await asyncio.gather(
            pipe_data(remote_reader, writer),
            pipe_data(reader, remote_writer),
            return_exceptions=True
        )
    except Exception as e:
        print(f'SOCKS4 Error: {str(e)}')
        writer.close()
        await writer.wait_closed()

async def socks5_handler(reader, writer, version):
    try:
        nmethods_bytes = await reader.readexactly(1)
        nmethods = nmethods_bytes[0]
        methods = await reader.readexactly(nmethods)
        if 0 not in methods:
            raise AuthMethodNotSupported

        writer.write(struct.pack('!BB', 5, 0))  # NO AUTHENTICATION REQUIRED
        await writer.drain()

        version, cmd, rsv, atyp = await read_struct(reader, '!BBBB')
        if version != 5:
            raise SocksVersionIncorrect

        if cmd != 1:  # 1=connect
            raise UnsupportedCommand

        if atyp == 1:  # ipv4
            host = await reader.readexactly(4)
            hostname = socket.inet_ntop(socket.AF_INET, host)
        elif atyp == 3:  # domain
            length, = await read_struct(reader, '!B')
            hostname = (await reader.readexactly(length)).decode('ascii')
        elif atyp == 4:  # ipv6
            host = await reader.readexactly(16)
            hostname = socket.inet_ntop(socket.AF_INET6, host)
        else:
            raise AddressTypeNotSupported

        port, = await read_struct(reader, '!H')
        print(f'SOCKS5 connect to {hostname}:{port}')

        reader2, writer2 = await asyncio.open_connection(hostname, port)
        conn_socket = writer2.get_extra_info('socket')
        conn_ip, conn_port = conn_socket.getsockname()[0:2]
        conn_family = 1 if conn_socket.family == socket.AF_INET else 4

        writer.write(struct.pack('!BBBB', 5, 0, 0, conn_family))
        writer.write(socket.inet_pton(conn_socket.family, conn_ip))
        writer.write(struct.pack('!H', conn_port))
        await writer.drain()

        await asyncio.gather(
            pipe_data(reader2, writer),
            pipe_data(reader, writer2),
            return_exceptions=True
        )
    except Exception as e:
        print(f'SOCKS5 Error: {str(e)}')
        writer.close()
        await writer.wait_closed()

async def detect_protocol_and_process(reader, writer):
    try:
        header = await reader.readexactly(1)
        version = header[0]
        if version == 4:
            further_header = await reader.readexactly(7)  # Read the rest of the SOCKS4 header
            complete_header = header + further_header
            await socks4_handler(reader, writer, complete_header)
        elif version == 5:
            await socks5_handler(reader, writer, version)
        else:
            raise ValueError("Unsupported SOCKS version")
    except Exception as e:
        print(f'Connection Error: {str(e)}')
        writer.close()
        await writer.wait_closed()

async def main(addr, port):
    server = await asyncio.start_server(detect_protocol_and_process, addr, port)
    print(f'Serving on {addr}:{port}')
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    addr = '0.0.0.0'
    port = 1082
    asyncio.run(main(addr, port))