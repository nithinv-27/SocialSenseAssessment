from fastapi import APIRouter, Form, HTTPException, status, Depends
from typing import Annotated, List
from schemas.schema import User, Admin, Post, Reaction, Share, Comment
from sqlmodel import Session, select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy import case
from config.database import engine
from pydantic import EmailStr
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta, timezone
import matplotlib.dates as mdates
import io
import seaborn as sns
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Use non-GUI backend (safe for servers)
import matplotlib.pyplot as plt
from fastapi.responses import StreamingResponse
from models.model import Token
from task_scheduler import scheduler
from helpers import hash_password, verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_HOURS, oauth2_scheme, get_user_or_admin, validate_user_or_admin, run_scheduled_job

router = APIRouter()

@router.post("/user/signup", status_code=status.HTTP_201_CREATED)
def register_user(email: Annotated[EmailStr, Form()], password: Annotated[str, Form()], name: Annotated[str, Form()]):
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
        user = get_user_or_admin(email=email, role="user")
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
    

@router.get("/get-posts/{time_range}")
def get_posts(token: Annotated[str, Depends(oauth2_scheme)], time_range: str):
    try: # Parse time_range
        member, role = validate_user_or_admin(token)
        now = datetime.now(timezone.utc)
        try:
            if "," in time_range:
                # Expecting a custom range: "start,end"
                start_str, end_str = time_range.split(",")
                start_time = datetime.fromisoformat(start_str).replace(tzinfo=timezone.utc)
                end_time = datetime.fromisoformat(end_str).replace(tzinfo=timezone.utc)
            elif time_range == "today":
                start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
                end_time = now
            elif time_range == "week":
                start_time = now - timedelta(days=7)
                end_time = now
            elif time_range == "month":
                start_time = now - timedelta(days=30)
                end_time = now
            else:
                raise HTTPException(status_code=400, detail="Invalid time_range format")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid time_range: {str(e)}")

        # Fetch posts
        with Session(engine) as session:
            if role == "admin":
                statement = select(Post).where(
                    Post.timestamp >= start_time,
                    Post.timestamp <= end_time
                ).order_by(Post.timestamp)
            else:
                statement = select(Post).where(
                    Post.user_id == member.id,
                    Post.timestamp >= start_time,
                    Post.timestamp <= end_time
                ).order_by(Post.timestamp)
            
            posts: List[Post] = session.exec(statement).all()

        return posts
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching posts! {str(e)}")
    
@router.post("/post/{post_id}/comment")
def comment_post(content: Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user, role = validate_user_or_admin(token)
        if role!="user":
            raise credentials_exception
        with Session(engine) as session:
            check_statement = select(Post).where(Post.id == post_id)
            check_result = session.exec(check_statement).first()
            if check_result is None:
                raise HTTPException(status_code=400, detail="No post found!")
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

@router.post("/post/{post_id}/share")
def comment_post(token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user, role = validate_user_or_admin(token)
        if role!="user":
            raise credentials_exception
        with Session(engine) as session:
            check_statement = select(Post).where(Post.id == post_id)
            check_result = session.exec(check_statement).first()
            if check_result is None:
                raise HTTPException(status_code=400, detail="No post found!")
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
    
@router.post("/post/{post_id}/{reactionType}")
def react_to_post(token: Annotated[str, Depends(oauth2_scheme)], post_id:int, reactionType:str):
    if reactionType not in ["like", "praise", "empathy", "interest", "appreciation"]:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Reaction type not found!")
    try:
        credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
        )
        user, role = validate_user_or_admin(token)
        if role != "user":
            raise credentials_exception
        with Session(engine) as session:
            check_statement = select(Post).where(Post.id == post_id)
            check_result = session.exec(check_statement).first()
            if check_result is None:
                raise HTTPException(status_code=400, detail="No post found!")
            statement = select(Reaction).where( (Reaction.user_id == user.id) & (Reaction.post_id == post_id) )
            result = session.exec(statement).first()

            if result is None:
                sample_reaction = Reaction(reactionType=reactionType, user_id=user.id, post_id=post_id)
                session.add(sample_reaction)

            elif result.reactionType == reactionType:
                session.delete(result)

            else:
                result.reactionType = reactionType
                result.timestamp = datetime.now(timezone.utc)
                session.add(result)

            session.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reacting. {str(e)}")
    
@router.delete("/post/{post_id}/delete-post")
def delete_user_post(token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    try:
        member, role = validate_user_or_admin(token)
        with Session(engine) as session:
            if role == "admin":
                statement = select(Post).where( (Post.id==post_id) )
            else:
                statement = select(Post).where( (Post.id==post_id) & (Post.user_id==member.id) )
            result = session.exec(statement).first()
            if result is None:
                raise HTTPException(status_code=400, detail="Post not found!")
            session.delete(result)
            session.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error deleting post! {str(e)}")

@router.post("/schedule-post")
def schedule_post(content: Annotated[str, Form()], scheduled_time:Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
        )
        user, role = validate_user_or_admin(token)
        if role != "user":
            raise credentials_exception
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
            sample_post = Post(content=content, timestamp=scheduled_time, user_id=user.id, status="scheduled")
            session.add(sample_post)
            session.commit()
            scheduler.add_job(func=run_scheduled_job, trigger='date', run_date=scheduled_time, max_instances=1000, misfire_grace_time=60, kwargs={'user_id':user.id, 'post_id':sample_post.id})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error scheduling post! {str(e)}")


@router.post("/post-now")
def create_post(content: Annotated[str, Form()], token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user, role = validate_user_or_admin(token)
        if role != "user":
            raise credentials_exception
        with Session(engine) as session:
            sample_post = Post(content=content, user_id=user.id)

            session.add(sample_post)

            session.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating post. {str(e)}")
    
@router.get("/post/{post_id}/reactions-plot")
def get_post_reactions_plot(token: Annotated[str, Depends(oauth2_scheme)], post_id: int):
    try:
        member, role = validate_user_or_admin(token)
        with Session(engine) as session:
            if role == "admin":
                statement = select(Post).where( (Post.id == post_id) )
            else:
                statement = select(Post).where( (Post.id==post_id) & (Post.user_id==member.id) )
            result = session.exec(statement).first()
            if result is None:
                raise HTTPException(status_code=400, detail="Post not found!")
            
            with Session(engine) as session:
                statement = (
                    select(
                        func.date_trunc("hour", Reaction.timestamp).label("time"),
                        func.count().label("total_reactions")
                    )
                    .where(Reaction.post_id == post_id)
                    .group_by(func.date_trunc("hour", Reaction.timestamp))
                )

                results = session.exec(statement).all()

            time_ls = []
            total_react = []

            for row in results:
                time_ls.append(row.time)
                total_react.append(row.total_reactions)

            preSum = [0]*(len(total_react)+1)

            for i in range(len(total_react)):
                preSum[i+1] = preSum[i] + total_react[i]

            df = pd.DataFrame(results, columns=["time", "total_reactions"])

            if df.empty:
                # Return empty image if no data
                plt.figure(figsize=(6, 3))
                plt.text(0.5, 0.5, "No reaction data found", ha="center", va="center", fontsize=14)
                plt.axis("off")
            else:
                df["time"] = pd.to_datetime(df["time"])
                df = df.set_index("time").asfreq("H", fill_value=0).reset_index()

                plt.figure(figsize=(10, 5))
                # sns.lineplot(data=df, x="time", y="total_reactions", marker="o")
                plt.plot(time_ls, preSum[1:], marker="o")
                plt.title(f"Reactions over Time (Post ID: {post_id})", fontsize=14)
                plt.xlabel("Time (hourly)")
                plt.ylabel("Total Reactions")

                ax = plt.gca()
                ax.set_xticks(time_ls)  # Only show your timestamps
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))  # Format as hour:minute

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
    
@router.get("/post/{post_id}/analytics")
def get_post_analytics(token: Annotated[str, Depends(oauth2_scheme)], post_id:int):
    try:
        member, role = validate_user_or_admin(token)
        with Session(engine) as session:
            if role == "admin":
                statement = select(Post).where( (Post.id == post_id) )
            else:
                statement = select(Post).where( (Post.id==post_id) & (Post.user_id==member.id) )
            posts = session.exec(statement).first()
            if posts is None:
                raise HTTPException(status_code=400, detail="Post not found!")
            
            reactions_statement = (
                select(
                    func.sum(case((Reaction.reactionType == "like", 1), else_=0)).label("like"),
                    func.sum(case((Reaction.reactionType == "praise", 1), else_=0)).label("praise"),
                    func.sum(case((Reaction.reactionType == "empathy", 1), else_=0)).label("empathy"),
                    func.sum(case((Reaction.reactionType == "interest", 1), else_=0)).label("interest"),
                    func.sum(case((Reaction.reactionType == "appreciation", 1), else_=0)).label("appreciation"),
                )
                .where(Reaction.post_id == post_id)
            )

            result = session.exec(reactions_statement).first()

                # Count comments
            comment_count_statement = (
                select(func.count(Comment.id)).where(Comment.post_id == post_id)
            )
            comment_count = session.exec(comment_count_statement).first() or 0

            # Count shares
            share_count_statement = (
                select(func.count(Share.id)).where(Share.post_id == post_id)
            )
            share_count = session.exec(share_count_statement).first() or 0

            engagement_np = np.array([
                result.like or 0,
                result.praise or 0,
                result.empathy or 0,
                result.interest or 0,
                result.appreciation or 0,
                posts.impression if posts and posts.impression is not None else 0,
                comment_count or 0,
                share_count or 0
            ], dtype=int)

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
    

""" ****************** ADMIN ROUTES ********************** """

@router.post("/admin/signup", status_code=status.HTTP_201_CREATED)
def register_admin(email: Annotated[EmailStr, Form()], password: Annotated[str, Form()], name: Annotated[str, Form()]):
    hashed_password = hash_password(password=password)

    with Session(engine) as session:
        try:
            new_admin = Admin(email=email, password=hashed_password, name=name)
            session.add(new_admin)
            session.commit()
            session.refresh(new_admin)
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

    return {"message": "Admin created successfully"}

@router.post("/admin/login")
def login_admin(email: Annotated[EmailStr, Form()], password: Annotated[str, Form()]):
    try:
        admin = get_user_or_admin(email=email, role="admin")
        if admin is None or not verify_password(password, admin.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
        access_token = create_access_token(email=email, expires_delta=access_token_expires, role="admin")
        return Token(access_token=access_token, token_type="bearer")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error Logging in. {str(e)}")