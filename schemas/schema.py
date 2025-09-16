from sqlmodel import Field, SQLModel, Relationship
from pydantic import EmailStr
from typing import List
from datetime import datetime, timezone

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    password: str
    name: str
    access_token: str | None = None

    # Relationships with cascade delete
    posts: List["Post"] = Relationship(back_populates="user", cascade_delete=True)
    reactions: List["Reaction"] = Relationship(back_populates="user", cascade_delete=True)
    shares: List["Share"] = Relationship(back_populates="user", cascade_delete=True)
    comments: List["Comment"] = Relationship(back_populates="user", cascade_delete=True)

class Admin(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    password: str
    name: str

class Post(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content:str
    impression: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None
    status: str = "published"
    
    user_id: int | None = Field(default=None, foreign_key="user.id", ondelete="CASCADE")

    user: User | None = Relationship(back_populates="posts")
    reactions: List["Reaction"] = Relationship(back_populates="post", cascade_delete=True)
    shares: List["Share"] = Relationship(back_populates="post", cascade_delete=True)
    comments: List["Comment"] = Relationship(back_populates="post", cascade_delete=True)

class Reaction(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    reactionType: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user_id: int | None = Field(default=None, foreign_key="user.id", ondelete="CASCADE")
    post_id: int | None = Field(default=None, foreign_key="post.id", ondelete="CASCADE")

    user: User | None = Relationship(back_populates="reactions")
    post: Post | None = Relationship(back_populates="reactions")

class Share(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user_id: int | None = Field(default=None, foreign_key="user.id", ondelete="CASCADE")
    post_id: int | None = Field(default=None, foreign_key="post.id", ondelete="CASCADE")

    user: User | None = Relationship(back_populates="shares")
    post: Post | None = Relationship(back_populates="shares")

class Comment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user_id: int | None = Field(default=None, foreign_key="user.id", ondelete="CASCADE")
    post_id: int | None = Field(default=None, foreign_key="post.id", ondelete="CASCADE")

    user: User | None = Relationship(back_populates="comments")
    post: Post | None = Relationship(back_populates="comments")
