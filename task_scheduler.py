from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from config.database import url_object

jobstores = {
    'default': SQLAlchemyJobStore(url=url_object)
}

executors = {
    'default': ThreadPoolExecutor(100)
}

scheduler = AsyncIOScheduler(jobstores=jobstores, executors=executors)
