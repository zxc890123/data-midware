from pydantic import BaseModel
from typing import Literal
from uuid import UUID


class MFAConfigModel(BaseModel):
    protect: bool = None


class MFANewDataModel(BaseModel):
    name: str
    comment: str = None
    secret: str
    position: int
    algorithm: Literal['SHA1', 'SHA256', 'SHA512'] = 'SHA1'
    interval: int = 30
    digits: Literal[6, '6', 7, '7', 8, '8'] = 6


class MFAUpdateDataModel(BaseModel):
    id: UUID
    name: str = None
    comment: str = None
    secret: str = None
    position: int = None
    algorithm: Literal['SHA1', 'SHA256', 'SHA512', None] = None
    interval: int = None
    digits: Literal[6, '6', 7, '7', 8, '8', None] = None
