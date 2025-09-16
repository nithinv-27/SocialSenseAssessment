from fastapi import APIRouter, Form, HTTPException, status, Depends
from typing import Annotated, Union
from schemas.schema import User, Post, Reaction, Share, Comment, Schedule
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
from config.database import engine
from pydantic import EmailStr
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta, timezone
import jwt, os, io
import seaborn as sns
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Use non-GUI backend (safe for servers)
import matplotlib.pyplot as plt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse
from models.model import Token
from task_scheduler import scheduler
import logging, requests

router = APIRouter()

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

def get_user(email: str):
    with Session(engine) as session:
        statement = select(User).where(User.email == email)
        result = session.exec(statement)
        return result.first() 

# Function to create a JWT access token
def create_access_token(email: EmailStr, expires_delta: Union[timedelta, None] = None):

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15) # expires in 15 minutes

    payload = {
        "sub": email,
        "exp": expire  
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# User validation
def validate_user(token):
    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: EmailStr = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    # Retrieve user details from the database
    user = get_user(email=email)
    if user is None:
        raise credentials_exception
    return user

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


@router.post("/user/signup", status_code=status.HTTP_201_CREATED)
def register_user(email: Annotated[str, Form()], password: Annotated[str, Form()], name: Annotated[str, Form()]):
    hashed_password = hash_password(password=password)

    with Session(engine) as session:
        try:
            new_user = User(email=email, password=hashed_password, name=name)
            session.add(new_user)
            session.commit()
            session.refresh(new_user)  # get inserted row back
        except IntegrityError:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        except Exception as e:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unexpected error: {str(e)}"
            )

    return {"message": "User created successfully"}

@router.post("/user/login")
def login_user(email: Annotated[EmailStr, Form()], password: Annotated[str, Form()]):
    try:
        user = get_user(email=email)
        if user is None or not verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
        access_token = create_access_token(email=email, expires_delta=access_token_expires)
        return Token(access_token=access_token, token_type="bearer")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error Logging in. {str(e)}")
    

    
@router.post("/user/{post_id}/comment")
def comment_post(content: Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    try:
        user = validate_user(token)
        with Session(engine) as session:
            sample_comment = Comment(content=content, user_id=user.id, post_id=post_id)

            session.add(sample_comment)

            session.commit()

            statement = select(Post).where(Post.id==post_id)
            result = session.exec(statement).first()
            result.comment+=1

            session.add(result)
            session.commit()

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error posting comment. {str(e)}")

@router.post("/user/{post_id}/share")
def comment_post(token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    try:
        user = validate_user(token)
        with Session(engine) as session:
            sample_share = Share(user_id=user.id, post_id=post_id)

            session.add(sample_share)

            session.commit()
            statement = select(Post).where(Post.id==post_id)
            result = session.exec(statement).first()
            result.share+=1

            session.add(result)
            session.commit()

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error sharing post. {str(e)}")
    
@router.post("/user/{post_id}/{reactionType}")
def react_to_post(token: Annotated[str, Depends(oauth2_scheme)], post_id:int, reactionType:str):
    if reactionType not in ["like", "praise", "empathy", "interest", "appreciation"]:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Reaction type not found!")
    try:
        user = validate_user(token)
        with Session(engine) as session:
            statement = select(Reaction).where( (Reaction.user_id == user.id) & (Reaction.post_id == post_id) )
            result = session.exec(statement).first()

            other_statement = select(Post).where(Post.id == post_id)
            other_result = session.exec(other_statement).first()

            if result is None:
                sample_reaction = Reaction(reactionType=reactionType, user_id=user.id, post_id=post_id)
                session.add(sample_reaction)
                setattr(other_result, reactionType, getattr(other_result, reactionType)+1)

            elif result.reactionType == reactionType:
                session.delete(result)
                setattr(other_result, reactionType, getattr(other_result, reactionType)-1)

            else:
                setattr(other_result, result.reactionType, getattr(other_result, result.reactionType)-1)
                result.reactionType = reactionType
                result.timestamp = datetime.now(timezone.utc)
                session.add(result)
                setattr(other_result, reactionType, getattr(other_result, reactionType)+1)

            session.add(other_result)
            session.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reacting. {str(e)}")

@router.get("/user/{post_id}/analytics")
def get_post_analytics(token: Annotated[str, Depends(oauth2_scheme)], post_id:int):
    try:
        user = validate_user(token)
        with Session(engine) as session:
            statement = select(Post).where( (Post.id == post_id) & (Post.user_id == user.id) )
            result = session.exec(statement).first()
            if result is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found!")
            
            total_reactions = calculate_post_reactions(result)
            total_engagement = calculate_post_engagement(result)

            engagement_np = np.array([result.like, result.praise, result.empathy, result.interest, result.appreciation, result.impression, result.comment, result.share])

            engagement_names = np.array(["like", "praise", "empathy", "interest", "appreciation", "impression", "comment", "share"])

            engagement_df = pd.DataFrame({"metric": engagement_names, "value": engagement_np})

            sns.barplot(data=engagement_df, x="metric", y="value")
            plt.title("Post Engagement Metrics")
            plt.xticks(rotation=45)
            plt.tight_layout()

            # Save to buffer
            buf = io.BytesIO()
            plt.savefig(buf, format="png")
            plt.close()
            buf.seek(0)

            return StreamingResponse(buf, media_type="image/png")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching post analytics! {str(e)}")


@router.post("/user/schedule-post")
def schedule_post(content: Annotated[str, Form()], scheduled_time:Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        user = validate_user(token)
        # Format: 2024-07-21T11:00
        scheduled_time = scheduled_time.replace("T", " ")
        scheduled_time+=":00"
        scheduled_dt = datetime.strptime(scheduled_time, "%Y-%m-%d %H:%M:%S")
        scheduled_dt = scheduled_dt.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        scheduled_dt_utc = scheduled_dt.astimezone(timezone.utc)
        print(type(scheduled_dt_utc))
        print(str(datetime.now(timezone.utc)))
        # Format: 2024-07-21 11:00:00
        if scheduled_dt_utc <= datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Scheduled time already passed!")
        with Session(engine) as session:
            sample_post = Schedule(content=content, scheduled_at=scheduled_time, user_id=user.id)
            session.add(sample_post)
            session.commit()
            scheduler.add_job(func=run_scheduled_job, trigger='date', run_date=scheduled_time, max_instances=1000, misfire_grace_time=60, kwargs={'user_id':user.id, 'content':content})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error scheduling post! {str(e)}")


@router.post("/user/post-now")
def create_post(content: Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        user = validate_user(token)
        with Session(engine) as session:
            sample_post = Post(content=content, user_id=user.id)

            session.add(sample_post)

            session.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating post. {str(e)}")
    