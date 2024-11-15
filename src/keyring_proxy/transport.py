# mypy: disable-error-code="return-value, valid-type"

import abc
import contextlib
import dataclasses
import logging
from typing import AsyncGenerator

import keyring.backend
import keyring.credentials

from keyring_proxy import packets
from keyring_proxy.connection import Connection

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TransportClient:
    @abc.abstractmethod
    @contextlib.asynccontextmanager
    async def _connect(self) -> AsyncGenerator[Connection, None]: ...

    @contextlib.asynccontextmanager
    async def connect(self):
        async with self._connect() as conn:
            try:
                yield conn
            finally:
                await conn.close()

    async def communicate[T: packets.Response](self, req: packets.Request[T]) -> T:
        async with self.connect() as conn:
            response = await conn.send_request(req)
            await conn.send_request(packets.EOTRequest())
            return response


@dataclasses.dataclass(kw_only=True)
class TransportServer:
    backend: keyring.backend.KeyringBackend = dataclasses.field(default_factory=keyring.get_keyring)

    @abc.abstractmethod
    async def serve_forever(self):
        raise NotImplementedError

    async def _handle_conn(self, conn: Connection):
        while await conn.handle_request(self.backend):
            pass
