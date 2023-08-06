import json
import logging
import os

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from databases import Database
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from contextlib import asynccontextmanager


ip_access_list = {}
BLOCK_TIME_S = 10.0
BLOCK_RETRIES = 10

# global data:
global_data = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Init

    config_pathname = os.getenv("WTT_CONFIGPATH", "config/config.json")
    logging.info(f'FastAPI Lifespan Startup, config: {config_pathname}')
    with open(config_pathname, 'r') as fp:
        global_data['config'] = json.load(fp)

    global database
    database = Database(global_data['config']['db_url'])
    engine = create_engine(global_data['config']['db_url'], connect_args={'check_same_thread': False}, echo=True)
    global SessionLocal
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    yield

    logging.info(f'FastAPI Lifespan Shutdown')
    global_data.clear(lifespan=lifespan)

# TODO: https://www.fastapitutorial.com/blog/database-connection-fastapi/  -> config!

app = FastAPI(lifespan=lifespan)
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)


class Event(Base):
    __tablename__ = "logevent"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String)
    timestamp = Column(DateTime, default=datetime.now)
    user = Column(String)


class EventEntry(BaseModel):
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.now)  # or .utcnow
    
    # @validator("timestamp")
    # def ensure_date_range(cls, v):
    #     if not datetime(year=1980, month=1, day=1) <= v < datetime(year=2100, month=1, day=1):
    #         raise ValueError("Must be in range")
    #     return v

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
async def startup():
    await database.connect()
    Base.metadata.create_all(bind=engine)


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.post("/register")
async def register(username: str, password: str, request: Request, db=Depends(get_db)):
    hashed_password = pwd_context.hash(password)
    user = User(username=username, password_hash=hashed_password)
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}


@app.get("/items")
async def get_items(request: Request, credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    user = authenticate_user(credentials, db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"items": ["item1", "item2", "item3"]}


@app.post("/logevent")
# async def log_event(event_type: str, credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
async def log_event(event_entry: EventEntry, request: Request, credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    user = authenticate_user(credentials, db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    event = Event(event_type=event_entry.event_type, user=user.username)
    db.add(event)
    db.commit()
    return {"message": "Event logged successfully"}


@app.get("/logevent")
async def get_events(request: Request, credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    user = authenticate_user(credentials, db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    events = db.query(Event).all()
    return {"events": [str(event.timestamp) + ": " + event.event_type for event in events]}


# authentication with some brute force defence
def authenticate_user(credentials: HTTPBasicCredentials, db, request: Request):
    client_host = request.client.host

    global ip_access_list
    if client_host in ip_access_list:
        if ip_access_list[client_host]['count'] >= BLOCK_RETRIES:
            # never accept this IP anymore
            return None
        if (datetime.now() - ip_access_list[client_host]['last_fail']) < timedelta(seconds=BLOCK_TIME_S):
            # first wait the blocking time, do not accept any actions on the API on waiting this time
            return None

    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not pwd_context.verify(credentials.password, user.password_hash):
        if client_host not in ip_access_list:
            ip_access_list[client_host] = {'last_fail': datetime.now(), 'count': 0}
        ip_access_list[client_host]['count'] += 1
        if ip_access_list[client_host]['count'] == BLOCK_RETRIES:
            logging.error(f'too many authentication tries from {client_host} -> blocked!')
        return None

    if client_host in ip_access_list:
        # if successfully logged in remove this user from the access_list
        del ip_access_list[client_host]
    return user


if __name__ == "__main__":
    import uvicorn

    # proxy_headers=True means: keep source IP address if the request is forwarded from nginx etc.
    uvicorn.run(app, host="0.0.0.0", port=8000, proxy_headers=True)
