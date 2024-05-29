import abc
import dataclasses
import json
import typing
from types import UnionType
from typing import Any, ClassVar, Self, Type, TypedDict, TypeVar, Union, get_args, get_origin, overload

import keyring.backend
import keyring.credentials

if typing.TYPE_CHECKING:
    from _typeshed import DataclassInstance
else:
    DataclassInstance = object


class SuccessResponse(TypedDict):
    result: Any


@dataclasses.dataclass
class Credential:
    username: str | None
    password: str | None

    def to_keyring_cred(self) -> keyring.credentials.Credential:
        return keyring.credentials.SimpleCredential(self.username, self.password)

    @classmethod
    def from_keyring_cred(cls, cred: keyring.credentials.Credential) -> Self:
        return cls(cred.username, cred.password)


@dataclasses.dataclass
class ErrorResponse:
    error: str


@dataclasses.dataclass
class DeleteResponse:
    result: bool


@dataclasses.dataclass
class DeleteRequest:
    command: ClassVar = "del"
    service: str
    username: str

    @classmethod
    def get_reponse_cls(cls) -> Type[DeleteResponse]:
        return DeleteResponse


@dataclasses.dataclass
class GetResponse:
    result: str | None


@dataclasses.dataclass
class GetRequest:
    command: ClassVar = "get"
    service: str
    username: str

    @classmethod
    def get_reponse_cls(cls) -> Type[GetResponse]:
        return GetResponse


@dataclasses.dataclass
class SetResponse:
    result: bool


@dataclasses.dataclass
class SetRequest:
    command: ClassVar = "set"
    service: str
    username: str
    password: str

    @classmethod
    def get_reponse_cls(cls) -> Type[SetResponse]:
        return SetResponse


@dataclasses.dataclass
class CredResponse:
    result: Credential | None


@dataclasses.dataclass
class CredRequest:
    command: ClassVar = "cred"
    service: str
    username: str | None = None

    @classmethod
    def get_reponse_cls(cls) -> Type[CredResponse]:
        return CredResponse


Requests = GetRequest | SetRequest | DeleteRequest | CredRequest
Responses = GetResponse | SetResponse | DeleteResponse | CredResponse | ErrorResponse

ReqPacket = str
RespPacket = str


def is_union(t: object) -> bool:
    origin = get_origin(t)
    return origin is Union or origin is UnionType


def parse_cls(cls: Type[Any]) -> tuple[Type[Any], bool]:
    if not is_union(cls):
        return cls, False
    args = get_args(cls)
    for arg in args:
        if dataclasses.is_dataclass(arg):
            return arg, True
    return cls, False


def _unpack(cls: Type[Any], data: Any, opt: bool = False) -> Any:
    if opt and data is None:
        return None

    cls, is_opt = parse_cls(cls)

    if not dataclasses.is_dataclass(cls):
        return data

    fields = dataclasses.fields(cls)

    dct = {field.name: _unpack(field.type, data[field.name], is_opt) for field in fields}

    return cls(**dct)


T = TypeVar("T", bound=DataclassInstance)


def _unpack_response[T](cls: Type[T], data: RespPacket) -> T:
    dct = json.loads(data)
    if "error" in dct:
        raise ValueError(dct["error"])
    return _unpack(cls, dct)


def _unpack_request(data: ReqPacket) -> Requests:
    dct = json.loads(data)
    command = dct["command"]
    match command:
        case "get":
            return _unpack(GetRequest, dct)
        case "set":
            return _unpack(SetRequest, dct)
        case "del":
            return _unpack(DeleteRequest, dct)
        case "cred":
            return _unpack(CredRequest, dct)
        case _:
            raise ValueError(f"Unknown command: {command!r}")


def _pack_request(obj: Requests) -> ReqPacket:
    req = dataclasses.asdict(obj)
    req["command"] = obj.command
    return json.dumps(req)


def _pack_response(obj: Responses) -> RespPacket:
    return json.dumps(dataclasses.asdict(obj))


@dataclasses.dataclass
class TransportClient:
    @abc.abstractmethod
    def _communicate(self, req: ReqPacket) -> RespPacket:
        pass

    @overload
    def communicate(self, req: GetRequest) -> GetResponse: ...

    @overload
    def communicate(self, req: SetRequest) -> SetResponse: ...

    @overload
    def communicate(self, req: DeleteRequest) -> DeleteResponse: ...

    @overload
    def communicate(self, req: CredRequest) -> CredResponse: ...

    def communicate(self, req: Requests) -> Responses:
        req_data = _pack_request(req)
        resp_data = self._communicate(req_data)
        match req:
            case GetRequest():
                return _unpack_response(GetResponse, resp_data)
            case SetRequest():
                return _unpack_response(SetResponse, resp_data)
            case DeleteRequest():
                return _unpack_response(DeleteResponse, resp_data)
            case CredRequest():
                return _unpack_response(CredResponse, resp_data)


class ProxyBackend(keyring.backend.KeyringBackend):

    @property
    def _transport(self):
        return self._get_transport()

    @abc.abstractmethod
    def _get_transport(self) -> TransportClient:
        pass

    def get_credential(self, service: str, username: str | None) -> keyring.credentials.Credential | None:
        result = self._transport.communicate(CredRequest(service, username)).result
        if result is None:
            return None
        return result.to_keyring_cred()

    def get_password(self, service: str, username: str) -> str | None:
        return self._transport.communicate(GetRequest(service, username)).result

    def set_password(self, service: str, username: str, password: str):
        self._transport.communicate(SetRequest(service, username, password))

    def delete_password(self, service: str, username: str):
        self._transport.communicate(DeleteRequest(service, username))


@dataclasses.dataclass
class TransportServer:
    backend: keyring.backend.KeyringBackend = dataclasses.field(default_factory=keyring.get_keyring)

    def _handle(self, req: Requests) -> Responses:
        match req:
            case GetRequest(service, username):
                return GetResponse(self.backend.get_password(service, username))
            case SetRequest(service, username, password):
                self.backend.set_password(service, username, password)
                return SetResponse(True)
            case DeleteRequest(service, username):
                self.backend.delete_password(service, username)
                return DeleteResponse(True)
            case CredRequest(service, username):
                cred = self.backend.get_credential(service, username)
                if cred is None:
                    return CredResponse(None)
                return CredResponse(Credential.from_keyring_cred(cred))

    def handle(self, req_data: ReqPacket) -> RespPacket:
        req = _unpack_request(req_data)
        resp = self._handle(req)
        return _pack_response(resp)
