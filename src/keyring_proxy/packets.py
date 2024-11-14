# mypy: disable-error-code="return-value, valid-type"

import abc
import json
import logging
from typing import (
    Annotated,
    Any,
    ClassVar,
    Literal,
    Protocol,
    Self,
    Type,
    Union,
    override,
)

import keyring.backend
import keyring.credentials
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class Response(Protocol):
    @property
    def cmd(self) -> str: ...

    def model_dump_json(self) -> str: ...


class Request[R: Response](Protocol):
    @property
    def cmd(self) -> str: ...

    def model_dump_json(self) -> str: ...

    def generate_response(self, backend: keyring.backend.KeyringBackend) -> R: ...

    def unpack_response(self, data: str) -> R: ...


class StaticRequest[R: Response](Request[R]):
    @classmethod
    def model_validate_json(cls, data: str) -> Self: ...

    @classmethod
    def model_validate(cls, data: dict[str, Any]) -> Self: ...

    def model_dump_json(self) -> str: ...


class Credential(BaseModel):
    username: str
    password: str

    def to_keyring_cred(self) -> keyring.credentials.Credential:
        return keyring.credentials.SimpleCredential(self.username, self.password)

    @classmethod
    def from_keyring_cred(cls, cred: keyring.credentials.Credential) -> Self:
        return cls(username=cred.username, password=cred.password)


class ResponseBase[T](BaseModel):
    typ: Literal["resp"] = "resp"
    result: T


class DeleteResponse(ResponseBase[bool]):
    cmd: Literal["del"] = "del"


class GetResponse(ResponseBase[str | None]):
    cmd: Literal["get"] = "get"


class SetResponse(ResponseBase[bool]):
    cmd: Literal["set"] = "set"


class CredentialResponse(ResponseBase[Credential | None]):
    cmd: Literal["cred"] = "cred"


_requests: dict[str, "type[StaticRequest[Response]]"] = {}


def unpack(line: str) -> "Request[Response]":
    data = json.loads(line)
    cmd = data["cmd"]
    req_cls = _requests[cmd]
    return req_cls.model_validate(data)


class RequestBase[T: Response](BaseModel):
    typ: Literal["req"] = "req"

    @classmethod
    def __pydantic_init_subclass__(cls, *args, **kwargs):
        super().__pydantic_init_subclass__(*args, **kwargs)
        cmd = cls.model_fields.get("cmd")
        if cmd is not None:
            _requests[cmd.default] = cls  # type: ignore

    @abc.abstractmethod
    def generate_response(self, backend: keyring.backend.KeyringBackend) -> T: ...

    @abc.abstractmethod
    def unpack_response(self, data: str) -> T: ...


class DeleteRequest(RequestBase[DeleteResponse]):
    cmd: Literal["del"] = "del"
    service: str
    username: str

    @override
    def unpack_response(self, data: str) -> DeleteResponse:
        return DeleteResponse.model_validate_json(data)

    @override
    def generate_response(self, backend: keyring.backend.KeyringBackend) -> DeleteResponse:
        try:
            backend.delete_password(self.service, self.username)
            return DeleteResponse(result=True)
        except Exception:
            return DeleteResponse(result=False)


class GetRequest(RequestBase[GetResponse]):
    cmd: Literal["get"] = "get"
    service: str
    username: str

    @override
    def unpack_response(self, data: str) -> GetResponse:
        return GetResponse.model_validate_json(data)

    @override
    def generate_response(self, backend: keyring.backend.KeyringBackend) -> GetResponse:
        try:
            return GetResponse(result=backend.get_password(self.service, self.username))
        except Exception:
            return GetResponse(result=None)


class SetRequest(RequestBase[SetResponse]):
    cmd: Literal["set"] = "set"
    service: str
    username: str
    password: str

    @override
    def unpack_response(self, data: str) -> SetResponse:
        return SetResponse.model_validate_json(data)

    @override
    def generate_response(self, backend: keyring.backend.KeyringBackend) -> SetResponse:
        try:
            backend.set_password(self.service, self.username, self.password)
            return SetResponse(result=True)
        except Exception:
            return SetResponse(result=False)


class CredentialRequest(RequestBase[CredentialResponse]):
    cmd: Literal["cred"] = "cred"
    service: str
    username: str | None = None

    @override
    def unpack_response(self, data: str) -> CredentialResponse:
        return CredentialResponse.model_validate_json(data)

    @override
    def generate_response(self, backend: keyring.backend.KeyringBackend) -> CredentialResponse:
        try:
            cred = backend.get_credential(self.service, self.username)
            if cred is None:
                return CredentialResponse(result=None)
            return CredentialResponse(result=Credential.from_keyring_cred(cred))
        except Exception:
            return CredentialResponse(result=None)
