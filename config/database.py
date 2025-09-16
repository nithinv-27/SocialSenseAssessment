from sqlmodel import create_engine, SQLModel
import psycopg2, os
from sqlalchemy.engine import URL
from dotenv import load_dotenv

load_dotenv("keys.env")

url_object = URL.create(
    "postgresql+psycopg2",
    username=os.getenv("DB_USERNAME"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("HOST"),        # just "localhost"
    port=int(os.getenv("PORT", 5432)),  # default 5432 if not set
    database=os.getenv("DB_NAME"),
)

engine = create_engine(url_object, echo=True)
