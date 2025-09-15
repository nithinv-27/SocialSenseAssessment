from pydantic import BaseModel, EmailStr
from typing import Union

class Token(BaseModel):
    access_token: str
    token_type: str