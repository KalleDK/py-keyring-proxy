import contextlib
import dataclasses
import logging
import os
import pathlib
import socket
from typing import override

import jaraco.classes.properties as properties  # type: ignore
from keyring_proxy.transport import ProxyBackend, ReqPacket, RespPacket, TransportClient, TransportServer

PRIORITY = 7.8
DEFAULT_SOCKET_PATH = "/tmp/keyring-proxy.sock"

logger = logging.getLogger(__name__)


def _get_socket() -> socket.socket:
    if os.name == "nt":
        raise NotImplementedError("Windows not supported")
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


@contextlib.contextmanager
def _listening_socket(socket_path: pathlib.Path):
    logger.info(f"starting up on {socket_path}")

    # Make sure the socket does not already exist
    if socket_path.exists():
        socket_path.unlink()
    sock = _get_socket()
    sock.bind(str(socket_path))
    sock.listen(1)
    with contextlib.closing(sock):
        yield sock


@contextlib.contextmanager
def _connection_socket(socket_path: pathlib.Path):
    # Create a UDS socket
    sock = _get_socket()

    # Connect the socket to the port where the server is listening
    logger.debug(f"connecting to {socket_path}")
    sock.connect(str(socket_path))
    with contextlib.closing(sock):
        yield sock


def _send_packet(sock: socket.socket, data: str):
    encoded_data = data.encode()
    amount_sending = len(encoded_data)
    sock.sendall(amount_sending.to_bytes(4, "big"))
    sock.sendall(encoded_data)


def _recv_exact(sock: socket.socket, amount_expected: int) -> bytes:
    encoded_resp = b""
    while len(encoded_resp) < amount_expected:
        encoded_resp += sock.recv(amount_expected - len(encoded_resp))
    return encoded_resp


def _recv_packet(sock: socket.socket):
    amount_expected = int.from_bytes(_recv_exact(sock, 4), "big")
    return _recv_exact(sock, amount_expected).decode()


@dataclasses.dataclass
class SocketClient(TransportClient):
    sock: pathlib.Path

    @override
    def _communicate(self, req: ReqPacket) -> RespPacket:
        with _connection_socket(self.sock) as sock:
            _send_packet(sock, req)
            return _recv_packet(sock)

    @classmethod
    def from_path(cls, sock: str):
        return cls(pathlib.Path(sock))


class SocketProxyBackend(ProxyBackend):

    socket: str = DEFAULT_SOCKET_PATH

    @override
    def _get_transport(self) -> TransportClient:
        return SocketClient.from_path(self.socket)

    @properties.classproperty
    def priority(cls):
        return PRIORITY


@dataclasses.dataclass
class SocketServer(TransportServer):

    socket_path: pathlib.Path = pathlib.Path(DEFAULT_SOCKET_PATH)

    def serve(self):
        with _listening_socket(self.socket_path) as sock:
            while True:
                # Wait for a connection
                logger.info("waiting for a connection")
                connection, client_address = sock.accept()
                with contextlib.closing(connection):
                    logger.debug(f"connection from {client_address}")
                    req = _recv_packet(connection)
                    logger.debug(f"received {req}")
                    resp = self.handle(req)
                    _send_packet(connection, resp)

    @classmethod
    def from_path(cls, sock: str = DEFAULT_SOCKET_PATH):
        return cls(socket_path=pathlib.Path(sock))
