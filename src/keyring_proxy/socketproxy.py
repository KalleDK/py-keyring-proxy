import abc
import contextlib
import dataclasses
import ipaddress
import logging
import os
import pathlib
import socket
from typing import override

from keyring_proxy.transport import ReqPacket, RespPacket, TransportClient, TransportServer

DEFAULT_UNIX_PATH = "/tmp/keyring-proxy/keyring-proxy.sock"
DEFAULT_TCP_PORT = 9731
DEFAULT_TCP_IP = ipaddress.IPv4Address("127.0.0.1")
DEFAULT_TCP_ADDR = (DEFAULT_TCP_IP, DEFAULT_TCP_PORT)

logger = logging.getLogger(__name__)

SOCKET_ADDR = str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]


@dataclasses.dataclass
class Connection:
    _sock: socket.socket

    def send_packet(self, data: str):
        encoded_data = data.encode()
        amount_sending = len(encoded_data)
        self._sock.sendall(amount_sending.to_bytes(4, "big"))
        self._sock.sendall(encoded_data)

    def recv_exact(self, amount_expected: int) -> bytes:
        encoded_resp = b""
        while len(encoded_resp) < amount_expected:
            encoded_resp += self._sock.recv(amount_expected - len(encoded_resp))
        return encoded_resp

    def recv_packet(self):
        amount_expected = int.from_bytes(self.recv_exact(4), "big")
        return self.recv_exact(amount_expected).decode()


@dataclasses.dataclass
class ListeningSocket:
    _sock: socket.socket

    @contextlib.contextmanager
    def accept(self):
        conn, cli = self._sock.accept()
        logger.debug(f"Accepted connection from {cli}")
        with contextlib.closing(conn):
            yield Connection(conn)


@dataclasses.dataclass
class SocketMgr:

    @abc.abstractmethod
    def _get_socket_type(self) -> socket.AddressFamily:
        pass

    def _get_socket(self) -> socket.socket:
        return socket.socket(self._get_socket_type(), socket.SOCK_STREAM)

    def _pre_bind(self):
        pass

    @abc.abstractmethod
    def _get_bind_addr(self) -> str | tuple[str, int]:
        pass

    @contextlib.contextmanager
    def listening_socket(self, backlog: int = 1):
        sock = self._get_socket()
        self._pre_bind()
        addr = self._get_bind_addr()
        logger.debug(f"Binding to {addr}")
        sock.bind(addr)
        sock.listen(backlog)
        with contextlib.closing(sock):
            yield ListeningSocket(sock)

    @contextlib.contextmanager
    def connect(self):
        sock = self._get_socket()
        addr = self._get_bind_addr()
        logger.debug(f"Connecting to {addr}")
        try:
            sock.connect(addr)
        except Exception as e:
            logger.error(f"Error connecting to {addr}: {e}")
            raise
        with contextlib.closing(sock):
            yield Connection(sock)


@dataclasses.dataclass
class UnixSocket(SocketMgr):
    path: pathlib.Path

    def _get_socket_type(self) -> socket.AddressFamily:
        if os.name == "nt":
            raise NotImplementedError("Windows not supported")
        return socket.AF_UNIX

    def _pre_bind(self):
        if self.path.exists():
            self.path.unlink()

    def _get_bind_addr(self) -> str:
        return str(self.path)


@dataclasses.dataclass
class TcpSocket(SocketMgr):
    host: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int

    def _get_socket_type(self) -> socket.AddressFamily:
        if isinstance(self.host, ipaddress.IPv6Address):
            return socket.AF_INET6
        return socket.AF_INET

    def _get_bind_addr(self) -> tuple[str, int]:
        return (str(self.host), self.port)


def socket_mgr(addr: SOCKET_ADDR):
    if isinstance(addr, (str, pathlib.Path)):
        return UnixSocket(pathlib.Path(addr))

    return TcpSocket(*addr)


def default_socket_mgr(
    path: str | pathlib.Path | None = None,
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    port: str | int | None = None,
):
    if path is not None:
        return socket_mgr(path)

    if ip is not None and port is not None:
        return socket_mgr((ipaddress.ip_address(ip), int(port)))

    if ip is not None:
        return socket_mgr((ipaddress.ip_address(ip), DEFAULT_TCP_PORT))

    if port is not None:
        return socket_mgr((DEFAULT_TCP_IP, int(port)))

    if os.name == "nt":
        return socket_mgr(DEFAULT_TCP_ADDR)
    return socket_mgr(DEFAULT_UNIX_PATH)


@dataclasses.dataclass
class SocketClient(TransportClient):
    sockmgr: SocketMgr = dataclasses.field(default_factory=lambda: socket_mgr(DEFAULT_UNIX_PATH))

    @override
    def _communicate(self, req: ReqPacket) -> RespPacket:
        with self.sockmgr.connect() as conn:
            logger.debug(f"Sending request: {req}")
            conn.send_packet(req)
            resp = conn.recv_packet()
            logger.debug(f"Received response: {resp}")
            return resp

    @classmethod
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]):
        return cls(socket_mgr(addr))


@dataclasses.dataclass
class SocketServer(TransportServer):

    sockmgr: SocketMgr = dataclasses.field(default_factory=lambda: socket_mgr(DEFAULT_UNIX_PATH))

    def serve(self):
        with self.sockmgr.listening_socket() as sock:
            while True:
                with sock.accept() as conn:
                    req = conn.recv_packet()
                    logger.debug(f"Received request: {req}")
                    resp = self.handle(req)
                    logger.debug(f"Sending response: {resp}")
                    conn.send_packet(resp)

    @classmethod
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]):
        return cls(sockmgr=socket_mgr(addr))
