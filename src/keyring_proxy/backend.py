import abc
import asyncio
import functools
import logging
from typing import Any, Callable, Coroutine

import keyring.backend
import keyring.credentials

from keyring_proxy.packets import CredentialRequest, DeleteRequest, GetRequest, SetRequest
from keyring_proxy.transport import TransportClient

logger = logging.getLogger(__name__)


def as_sync[R, **K](fn: Callable[K, Coroutine[Any, Any, R]]) -> Callable[K, R]:
    @functools.wraps(fn)
    def wrapped(*args: K.args, **kwargs: K.kwargs) -> R:
        return asyncio.run(fn(*args, **kwargs))

    return wrapped


class ProxyBackend(keyring.backend.KeyringBackend):
    logfile: str = "keyring-proxy.log"
    log: bool = False

    def __init__(self):
        super().__init__()
        if self.log:
            logging.basicConfig(level=logging.DEBUG)

    @property
    def _transport(self):
        return self._get_transport()

    @abc.abstractmethod
    def _get_transport(self) -> TransportClient:
        pass

    @as_sync
    async def get_credential(self, service: str, username: str | None) -> keyring.credentials.Credential | None:
        try:
            logger.debug(f"get_credential({service!r}, {username!r})")
            resp = await self._transport.communicate(CredentialRequest(service=service, username=username))
            result = resp.result
            if result is None:
                return None
            return result.to_keyring_cred()
        except Exception as e:
            logger.info(f"Error getting credential: {e}")
            return None

    @as_sync
    async def get_password(self, service: str, username: str) -> str | None:
        try:
            logger.debug(f"get_password({service!r}, {username!r})")
            return (await self._transport.communicate(GetRequest(service=service, username=username))).result
        except Exception as e:
            logger.info(f"Error getting password: {e}")
            return None

    @as_sync
    async def set_password(self, service: str, username: str, password: str):
        try:
            logger.debug(f"set_password({service!r}, {username!r}, {password!r})")
            await self._transport.communicate(SetRequest(service=service, username=username, password=password))
        except Exception as e:
            logger.info(f"Error setting password: {e}")
            return None

    @as_sync
    async def delete_password(self, service: str, username: str):
        try:
            logger.debug(f"delete_password({service!r}, {username!r})")
            await self._transport.communicate(DeleteRequest(service=service, username=username))
        except Exception as e:
            logger.info(f"Error deleting password: {e}")
            return None
