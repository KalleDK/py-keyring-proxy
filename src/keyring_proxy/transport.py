# mypy: disable-error-code="return-value, valid-type"

import abc
import dataclasses
import logging
from typing import (
    Annotated,
    Literal,
    Protocol,
    Self,
    Type,
    Union,
)

import keyring.backend
import keyring.credentials
from pydantic import BaseModel, Field, RootModel

logger = logging.getLogger(__name__)


class Credential(BaseModel):
    username: str
    password: str

    def to_keyring_cred(self) -> keyring.credentials.Credential:
        return keyring.credentials.SimpleCredential(self.username, self.password)

    @classmethod
    def from_keyring_cred(cls, cred: keyring.credentials.Credential) -> Self:
        return cls(username=cred.username, password=cred.password)


class ResponseBase(BaseModel):
    typ: Literal["resp"] = "resp"


class DeleteResponse(ResponseBase):
    cmd: Literal["del"] = "del"
    result: bool


class GetResponse(ResponseBase):
    cmd: Literal["get"] = "get"
    result: str | None


class SetResponse(ResponseBase):
    cmd: Literal["set"] = "set"
    result: bool


class CredentialResponse(ResponseBase):
    cmd: Literal["cred"] = "cred"
    result: Credential | None


class RequestBase(BaseModel):
    typ: Literal["req"] = "req"


class DeleteRequest(RequestBase):
    cmd: Literal["del"] = "del"
    service: str
    username: str

    def get_response_cls(self) -> Type[DeleteResponse]:
        return DeleteResponse


class GetRequest(RequestBase):
    cmd: Literal["get"] = "get"
    service: str
    username: str

    def get_response_cls(self) -> Type[GetResponse]:
        return GetResponse


class SetRequest(RequestBase):
    cmd: Literal["set"] = "set"
    service: str
    username: str
    password: str

    def get_response_cls(self) -> Type[SetResponse]:
        return SetResponse


class CredentialRequest(RequestBase):
    cmd: Literal["cred"] = "cred"
    service: str
    username: str | None = None

    def get_response_cls(self) -> Type[CredentialResponse]:
        return CredentialResponse


Request = Annotated[Union[DeleteRequest, GetRequest, SetRequest, CredentialRequest], Field(discriminator="cmd")]
Response = Annotated[Union[DeleteResponse, GetResponse, SetResponse, CredentialResponse], Field(discriminator="cmd")]

ReqPacket = str
RespPacket = str


class RequestP[T: Response](Protocol):
    @property
    def cmd(self) -> str: ...

    def model_dump_json(self) -> str: ...

    def get_response_cls(self) -> Type[T]: ...


@dataclasses.dataclass
class TransportClient:
    @abc.abstractmethod
    async def _communicate(self, req: ReqPacket) -> RespPacket:
        pass

    async def communicate[T: Response](self, req: RequestP[T]) -> T:
        req_data = req.model_dump_json()
        resp_data = await self._communicate(req_data)
        resp = req.get_response_cls().model_validate_json(resp_data)
        if resp.cmd != req.cmd:
            raise ValueError(f"Expected response command {req.cmd!r}, got {resp.cmd!r}")
        return resp


@dataclasses.dataclass(kw_only=True)
class TransportServer:
    backend: keyring.backend.KeyringBackend = dataclasses.field(default_factory=keyring.get_keyring)

    def _handle(self, req: Request) -> Response:
        if isinstance(req, GetRequest):
            return GetResponse(result=self.backend.get_password(req.service, req.username))
        if isinstance(req, SetRequest):
            self.backend.set_password(req.service, req.username, req.password)
            return SetResponse(result=True)
        if isinstance(req, DeleteRequest):
            self.backend.delete_password(req.service, req.username)
            return DeleteResponse(result=True)
        if isinstance(req, CredentialRequest):
            cred = self.backend.get_credential(req.service, req.username)
            if cred is None:
                return CredentialResponse(result=None)
            return CredentialResponse(result=Credential.from_keyring_cred(cred))

    def handle(self, req_data: ReqPacket) -> RespPacket:
        req = RootModel[Request].model_validate_json(req_data).root
        resp = self._handle(req)
        return resp.model_dump_json()
