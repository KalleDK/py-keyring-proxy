import abc
import contextlib
import dataclasses
import ipaddress
import logging
import os
import pathlib
import socket
from typing import NamedTuple, override

from keyring_proxy.transport import ReqPacket, RespPacket, TransportClient, TransportServer

DEFAULT_UNIX_PATH = "/tmp/keyring-proxy/keyring-proxy.sock"
DEFAULT_TCP_PORT = 9731
DEFAULT_TCP_IP = ipaddress.IPv4Address("127.0.0.1")
DEFAULT_TCP_HOST = ipaddress.IPv4Address("127.0.0.1")


logger = logging.getLogger(__name__)

SOCKET_ADDR = str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]


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


class SocketInfo(NamedTuple):
    family: socket.AddressFamily
    addr: str | tuple[str, int]


@dataclasses.dataclass
class SocketMgr:

    @abc.abstractmethod
    def _get_socket_info(self) -> list[SocketInfo]:
        pass

    def _create_socket(self, info: SocketInfo) -> socket.socket:
        return socket.socket(info.family, socket.SOCK_STREAM)

    def _pre_bind(self):
        pass

    @abc.abstractmethod
    def _get_bind_addr(self) -> str | tuple[str, int]:
        pass

    @contextlib.contextmanager
    def listening_socket(self, backlog: int = 1):
        info = self._get_socket_info()
        for i in info:
            try:
                logger.debug(f"Creating socket on {i.addr}")
                sock = self._create_socket(i)
                self._pre_bind()
                sock.bind(i.addr)
                sock.listen(backlog)
                break
            except Exception as e:
                logger.info(f"Error creating socket: {e}")
                continue
        else:
            raise RuntimeError("Failed to create socket")

        with contextlib.closing(sock):
            yield ListeningSocket(sock)

    @contextlib.contextmanager
    def connect(self):
        info = self._get_socket_info()
        for i in info:
            try:
                sock = self._create_socket(i)
                logger.debug(f"Connecting to {i.addr}")
                sock.connect(i.addr)
                break
            except Exception as e:
                logger.error(f"Error creating socket: {e}")
                continue
        else:
            raise RuntimeError("Failed to create socket")

        with contextlib.closing(sock):
            yield Connection(sock)


@dataclasses.dataclass
class UnixSocket(SocketMgr):
    path: pathlib.Path

    @override
    def _get_socket_info(self) -> list[SocketInfo]:
        if os.name == "nt":
            raise NotImplementedError("Windows not supported")
        return [SocketInfo(socket.AF_UNIX, str(self.path))]

    @override
    def _pre_bind(self):
        if self.path.exists():
            self.path.unlink()

    @override
    def _get_bind_addr(self) -> str:
        return str(self.path)


@dataclasses.dataclass
class TcpSocket(SocketMgr):
    host: ipaddress.IPv4Address | ipaddress.IPv6Address | str
    port: int

    @override
    def _get_socket_info(self) -> list[SocketInfo]:
        logger.debug(f"Resolving {self.host} {self.port}")
        info = socket.getaddrinfo(str(self.host), self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return [SocketInfo(family, (addr[0], addr[1])) for family, _, _, _, addr in info]

    @override
    def _get_bind_addr(self) -> tuple[str, int]:
        return (str(self.host), self.port)


def socket_mgr(addr: SOCKET_ADDR):
    if isinstance(addr, (str, pathlib.Path)):
        return UnixSocket(pathlib.Path(addr))

    return TcpSocket(*addr)


def default_socket_mgr_server(
    path: str | pathlib.Path | None = None,
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    port: str | int | None = None,
):
    if path is not None:
        return socket_mgr(path)

    if ip is not None and port is not None:
        return socket_mgr((ip, int(port)))

    if ip is not None:
        return socket_mgr((ip, DEFAULT_TCP_PORT))

    if port is not None:
        return socket_mgr((DEFAULT_TCP_IP, int(port)))

    if os.name == "nt":
        return socket_mgr((DEFAULT_TCP_IP, DEFAULT_TCP_PORT))
    return socket_mgr(DEFAULT_UNIX_PATH)


def default_socket_mgr_client(
    path: str | pathlib.Path | None = None,
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    port: str | int | None = None,
):
    if path is not None:
        return socket_mgr(path)

    if ip is not None and port is not None:
        return socket_mgr((ip, int(port)))

    if ip is not None:
        return socket_mgr((ip, DEFAULT_TCP_PORT))

    if port is not None:
        return socket_mgr((DEFAULT_TCP_HOST, int(port)))

    if os.name == "nt":
        return socket_mgr((DEFAULT_TCP_HOST, DEFAULT_TCP_PORT))
    return socket_mgr(DEFAULT_UNIX_PATH)


@dataclasses.dataclass
class SocketClient(TransportClient):
    sockmgr: SocketMgr = dataclasses.field(default_factory=default_socket_mgr_client)

    @override
    def _communicate(self, req: ReqPacket) -> RespPacket:
        with self.sockmgr.connect() as conn:
            logger.debug(f"Sending request: {req}")
            conn.send_packet(req)
            resp = conn.recv_packet()
            logger.debug(f"Received response: {resp}")
            return resp

    @classmethod
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]):
        return cls(socket_mgr(addr))


@dataclasses.dataclass
class SocketServer(TransportServer):

    sockmgr: SocketMgr = dataclasses.field(default_factory=default_socket_mgr_server)

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
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]):
        return cls(sockmgr=socket_mgr(addr))
