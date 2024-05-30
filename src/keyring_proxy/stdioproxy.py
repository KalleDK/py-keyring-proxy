import dataclasses
import logging
import pathlib
import shutil
import subprocess

from keyring_proxy.transport import (
    ReqPacket,
    RespPacket,
    TransportClient,
    TransportServer,
)

DEFAULT_EXE_PATH = "keyring-proxy.exe"
COMMAND_NAME = "json"

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class RuntimeTransport(TransportClient):
    exe_path: pathlib.Path

    def _communicate(self, req: ReqPacket) -> RespPacket:
        r = subprocess.run([self.exe_path, COMMAND_NAME, req], capture_output=True)
        r.check_returncode()
        lines = [line for line in r.stdout.decode().splitlines() if line != ""]
        result = lines.pop()
        for line in lines:
            logger.info(line)
        return result

    @classmethod
    def from_path(cls, exe_path: str):
        exe_path_full = shutil.which(exe_path)
        if exe_path_full is None:
            raise FileNotFoundError(f"Could not find {exe_path!r}")
        return cls(pathlib.Path(exe_path_full))


@dataclasses.dataclass
class StdioProxyFrontend(TransportServer):
    pass
