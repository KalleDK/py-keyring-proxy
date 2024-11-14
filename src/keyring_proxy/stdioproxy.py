import asyncio
import contextlib
import dataclasses
import logging
import pathlib
import shutil
import subprocess
import sys
from typing import AsyncGenerator, BinaryIO, override

from keyring_proxy.connection import AsyncConnection, Connection, IOConnection
from keyring_proxy.transport import (
    TransportClient,
    TransportServer,
)

DEFAULT_EXE_PATH = "keyring-proxy.exe"
COMMAND_NAME = "json"

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class StdioClient(TransportClient):
    exe_path: pathlib.Path

    @override
    @contextlib.asynccontextmanager
    async def _connect(self) -> AsyncGenerator[Connection, None]:
        proc = await asyncio.create_subprocess_exec(
            str(self.exe_path),
            COMMAND_NAME,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if proc.stdin is None or proc.stdout is None:
            raise ValueError("Could not open stdin/stdout for subprocess")
        try:
            yield AsyncConnection(proc.stdout, proc.stdin)
        finally:
            logger.info("Closing connection")
            await proc.communicate()
            logger.info("Connection closed")

    @classmethod
    def from_path(cls, exe_path: str):
        exe_path_full = shutil.which(exe_path)
        if exe_path_full is None:
            raise FileNotFoundError(f"Could not find {exe_path!r}")
        return cls(pathlib.Path(exe_path_full))


@dataclasses.dataclass
class StdioServer(TransportServer):
    stdin: BinaryIO
    stdout: BinaryIO

    async def serve_forever(self):
        conn = IOConnection(self.stdin, self.stdout)
        # while not conn.is_closing():
        try:
            logger.info("Handling new connection")
            await self._handle_conn(conn)
        except Exception as e:
            logger.exception(f"Error handling request {e}")

    @classmethod
    def from_stdio(cls):
        return cls(sys.stdin.buffer, sys.stdout.buffer)
