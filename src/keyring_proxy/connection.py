import abc
import asyncio
import dataclasses
import logging
import sys
from typing import BinaryIO, override

import keyring
import keyring.backend

from keyring_proxy import packets

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Connection:
    @abc.abstractmethod
    async def send_packet(self, data: str):
        raise NotImplementedError

    @abc.abstractmethod
    async def recv_packet(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    async def close(self):
        raise NotImplementedError

    @abc.abstractmethod
    def is_closing(self) -> bool:
        raise NotImplementedError

    async def send_request[T: packets.Response](self, req: packets.Request[T]) -> T:
        req_data = req.model_dump_json()
        logger.debug(f"Sending request: {req_data}")
        await self.send_packet(req_data)
        resp_data = await self.recv_packet()
        logger.debug(f"Received response: {resp_data}")
        resp = req.unpack_response(resp_data)
        if resp.cmd != req.cmd:
            raise ValueError(f"Expected response command {req.cmd!r}, got {resp.cmd!r}")
        return resp

    async def handle_request(self, backend: keyring.backend.KeyringBackend):
        logger.info("Handling new connection")
        try:
            req_data = await self.recv_packet()
            logger.debug(f"Received request: {req_data}")
            req = packets.unpack(req_data)
            resp = req.generate_response(backend)
            resp_data = resp.model_dump_json()
            logger.debug(f"Sending response: {resp_data}")
            await self.send_packet(resp_data)
        except Exception as e:
            logger.exception(f"Error handling request {e}")


@dataclasses.dataclass
class AsyncConnection(Connection):
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    @override
    def is_closing(self) -> bool:
        return self._writer.is_closing()

    @override
    async def send_packet(self, data: str):
        encoded_data = data.encode()
        amount_sending = len(encoded_data)
        self._writer.write(amount_sending.to_bytes(4, "big"))
        self._writer.write(encoded_data)
        await self._writer.drain()

    @override
    async def recv_packet(self):
        amount_expected = int.from_bytes(await self._reader.readexactly(4), "big")
        return (await self._reader.readexactly(amount_expected)).decode()

    @override
    async def close(self):
        self._writer.close()
        await self._writer.wait_closed()

    @classmethod
    def from_stream(cls, io: tuple[asyncio.StreamReader, asyncio.StreamWriter]):
        reader, writer = io
        return cls(reader, writer)


@dataclasses.dataclass
class IOConnection(Connection):
    _reader: BinaryIO
    _writer: BinaryIO

    def readexactly(self, amount_expected: int) -> bytes:
        logger.info(f"Reading {amount_expected} bytes")
        encoded_resp = b""
        while len(encoded_resp) < amount_expected:
            encoded_resp += self._reader.read(amount_expected - len(encoded_resp))
            logger.debug(f"Read {len(encoded_resp)} bytes")
        return encoded_resp

    @override
    def is_closing(self) -> bool:
        return self._writer.closed

    @override
    async def send_packet(self, data: str):
        encoded_data = data.encode()
        amount_sending = len(encoded_data)
        self._writer.write(amount_sending.to_bytes(4, "big"))
        self._writer.write(encoded_data)
        self._writer.flush()

    @override
    async def recv_packet(self):
        amount_expected = int.from_bytes(self.readexactly(4), "big")
        return self.readexactly(amount_expected).decode()

    @override
    async def close(self):
        self._writer.flush()
        self._writer.close()

    @classmethod
    def from_stdio(cls):
        reader, writer = sys.stdin.buffer, sys.stdout.buffer
        return cls(reader, writer)
