import abc
import asyncio
import contextlib
import dataclasses
import ipaddress
import logging
import pathlib
import sys
from typing import Any, Callable, Coroutine, override

from keyring_proxy.transport import ReqPacket, RespPacket, TransportClient, TransportServer

DEFAULT_UNIX_PATH = "/tmp/keyring-proxy/keyring-proxy.sock"
DEFAULT_TCP_PORT = 9731
DEFAULT_TCP_IP = ipaddress.IPv4Address("127.0.0.1")
DEFAULT_TCP_HOST = ipaddress.IPv4Address("127.0.0.1")


logger = logging.getLogger(__name__)

SOCKET_ADDR = str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]


@dataclasses.dataclass
class Connection:
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    async def send_packet(self, data: str):
        encoded_data = data.encode()
        amount_sending = len(encoded_data)
        self._writer.write(amount_sending.to_bytes(4, "big"))
        self._writer.write(encoded_data)
        await self._writer.drain()

    async def recv_packet(self):
        amount_expected = int.from_bytes(await self._reader.readexactly(4), "big")
        return (await self._reader.readexactly(amount_expected)).decode()

    async def close(self):
        self._writer.close()
        await self._writer.wait_closed()

    @classmethod
    def from_stream(cls, io: tuple[asyncio.StreamReader, asyncio.StreamWriter]):
        reader, writer = io
        return cls(reader, writer)


@dataclasses.dataclass
class SocketMgr:
    @abc.abstractmethod
    async def _create_server(
        self, handle: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, Any]]
    ) -> asyncio.AbstractServer: ...

    @abc.abstractmethod
    async def _connect_client(self) -> Connection:
        ...
        # return await asyncio.open_connection("localhost", 8888)

    async def _pre_bind(self):
        pass

    @contextlib.asynccontextmanager
    async def connect(self):
        conn = await self._connect_client()
        try:
            yield conn
        finally:
            await conn.close()

    @contextlib.asynccontextmanager
    async def create_server(
        self, handle: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, Any]]
    ):
        await self._pre_bind()
        server = await self._create_server(handle)
        try:
            yield server
        finally:
            server.close()
            await server.wait_closed()


@dataclasses.dataclass
class UnixSocket(SocketMgr):
    path: pathlib.Path

    @override
    async def _connect_client(self) -> Connection:
        return Connection.from_stream(await asyncio.open_unix_connection(str(self.path)))

    @override
    async def _create_server(
        self, handle: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, Any]]
    ):
        logger.info(f"Creating unix server on {self.path}")
        return await asyncio.start_unix_server(handle, path=str(self.path))

    @override
    async def _pre_bind(self):
        if self.path.exists():
            self.path.unlink()


@dataclasses.dataclass
class TcpSocket(SocketMgr):
    host: ipaddress.IPv4Address | ipaddress.IPv6Address | str
    port: int

    @override
    async def _connect_client(self) -> Connection:
        return Connection.from_stream(await asyncio.open_connection(str(self.host), self.port))

    @override
    async def _create_server(
        self, handle: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, Any]]
    ):
        logger.info(f"Creating tcp server on {self.host}:{self.port}")
        return await asyncio.start_server(handle, host=str(self.host), port=self.port)


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

    if sys.platform == "win32":
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

    if sys.platform == "win32":
        return socket_mgr((DEFAULT_TCP_HOST, DEFAULT_TCP_PORT))
    return socket_mgr(DEFAULT_UNIX_PATH)


@dataclasses.dataclass
class SocketClient(TransportClient):
    sockmgr: SocketMgr = dataclasses.field(default_factory=default_socket_mgr_client)

    @override
    async def _communicate(self, req: ReqPacket) -> RespPacket:
        async with self.sockmgr.connect() as conn:
            logger.debug(f"Sending request: {req}")
            await conn.send_packet(req)

            resp = await conn.recv_packet()
            logger.debug(f"Received response: {resp}")
            return resp

    @classmethod
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]):
        return cls(socket_mgr(addr))


@dataclasses.dataclass
class SocketServer(TransportServer):
    sockmgr: SocketMgr = dataclasses.field(default_factory=default_socket_mgr_server)

    async def _handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        logger.info("Handling new connection")
        try:
            conn = Connection.from_stream((reader, writer))
            req = await conn.recv_packet()
            logger.debug(f"Received request: {req}")
            resp = self.handle(req)
            logger.debug(f"Sending response: {resp}")
            await conn.send_packet(resp)
        except Exception as e:
            logger.exception("Error handling request")

    async def serve_forever(self):
        async with self.sockmgr.create_server(self._handle_stream) as server:
            await server.serve_forever()

    @classmethod
    def from_path(cls, addr: str | pathlib.Path | tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int]):
        return cls(sockmgr=socket_mgr(addr))
