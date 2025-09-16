from sqlmodel import Field, SQLModel
from pydantic import EmailStr
from datetime import datetime, timezone

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    password: str
    name: str
    access_token: str | None = None

class Admin(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    password: str
    name: str

class Post(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content:str
    like: int = 0
    praise: int = 0
    empathy: int = 0
    interest: int = 0
    appreciation: int = 0
    impression: int = 0
    comment: int = 0
    share: int = 0
    timestamp: datetime = datetime.now(timezone.utc)
    user_id: int | None = Field(default=None, foreign_key="user.id")

class Reaction(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    reactionType: str
    timestamp: datetime = datetime.now(timezone.utc)
    user_id: int | None = Field(default=None, foreign_key="user.id")
    post_id: int | None = Field(default=None, foreign_key="post.id")

class Share(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = datetime.now(timezone.utc)
    user_id: int | None = Field(default=None, foreign_key="user.id")
    post_id: int | None = Field(default=None, foreign_key="post.id")

class Comment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str
    timestamp: datetime = datetime.now(timezone.utc)
    user_id: int | None = Field(default=None, foreign_key="user.id")
    post_id: int | None = Field(default=None, foreign_key="post.id")

class Schedule(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str
    created_on: datetime = datetime.now(timezone.utc)
    scheduled_at: str
    error: str | None = None
    status: str = "Scheduled"
    user_id: int | None = Field(default=None, foreign_key="user.id")

