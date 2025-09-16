import jwt, os
from typing import Union
from pydantic import EmailStr
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from dotenv import load_dotenv
import logging, requests
from sqlmodel import Session, select
from config.database import engine
from schemas.schema import User, Admin, Post, Schedule


load_dotenv("keys.env") 

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS=1

# Password hashing context using bcrypt
pass_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Helper function to hash user passwords
def hash_password(password):
    return pass_context.hash(password)

# Helper function to verify hashed passwords
def verify_password(password, hashed_password):
    return pass_context.verify(password, hashed_password)

def get_user_or_admin(email: str, role:str):
    with Session(engine) as session:
        if role=="user":
            statement = select(User).where(User.email == email)
        else:
            statement = select(Admin).where(Admin.email == email)
        result = session.exec(statement)
        return result.first() 

# Function to create a JWT access token
def create_access_token(email: EmailStr, expires_delta: Union[timedelta, None] = None, role:str = "user"):

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15) # expires in 15 minutes

    payload = {
        "sub": email,
        "role":role,
        "exp": expire  
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# User validation
def validate_user_or_admin(token):
    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: EmailStr = payload.get("sub")
        role: str = payload.get("role")
        if email is None or role not in ["user", "admin"]:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    
    # Retrieve user details from the database
    member = get_user_or_admin(email=email, role=role)
    if member is None:
        raise credentials_exception
    return member, role

# Calculate Post Reactions
def calculate_post_reactions(post: Post):
    total_reactions = post.like + post.praise + post.empathy + post.interest + post.appreciation
    return total_reactions

# Calculate Post Engagement
def calculate_post_engagement(post: Post):
    total_reactions = calculate_post_reactions(post)
    total_engagement = total_reactions + post.comment + post.share
    return total_engagement

# Run Scheduled Job Function
def run_scheduled_job(user_id, content):
    try:
        with Session(engine) as session:
            statement = select(User).where(User.id == user_id)
            result = session.exec(statement).first()
            if result is None:
                logging.error(f"User {user_id} not found. Skipping job.")
                return
            access_token = result.access_token
            # Post using linkedin api logic goes here
            # headers = {"access_token":access_token}
            # data = {"content":content}
            # res = requests.post("https://api.linkedin.com/v2/ugcPosts", headers=headers, json=data)
            res = {"ok":True}
            other_statement = select(Schedule).where( (Schedule.user_id == user_id) & (Schedule.content == content) )
            other_result = session.exec(other_statement).first()
            if other_result is None:
                logging.error(msg="No job found!")
                return
            if not res.get("ok"):
                other_result.status = "Failed"
                other_result.error = res.get("text", "Error!!!")
                session.add(other_result)
                logging.error(msg="Failed to post!")
                session.commit()
                return
            other_result.status = "Published"
            new_post = Post(content=content, user_id=user_id)
            session.add(new_post)
            session.add(other_result)
            session.commit()
            return
    except Exception as e:
        logging.error(msg=f"Error in run_scheduled_job {str(e)}", exc_info=True)