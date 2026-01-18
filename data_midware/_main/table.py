from sqlalchemy import Column, Uuid, Text, Integer, Boolean, Float, BINARY, JSON, ForeignKey, UniqueConstraint

from uuid import uuid4, uuid7

from .._share.db import Base


class TB_USERS_MAIN(Base):
    __tablename__ = 'tb_users_main'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, default=uuid4, unique=True)  # unique自带index
    email = Column(BINARY, unique=True, nullable=False)
    email_mask = Column(Text, nullable=False)
    password = Column(BINARY, nullable=False)
    password_salt = Column(BINARY, nullable=False)
    data_key = Column(Text, nullable=False)
    admin = Column(Boolean, nullable=False, index=True)
    status = Column(Integer, nullable=False, index=True)
    created_time = Column(Float, nullable=False)
    created_ip = Column(Text, nullable=False)
    trashed_time = Column(Float, default=-1.0, nullable=False, index=True)
    trashed_ip = Column(Text)


class TB_USERS_OTHER(Base):
    __tablename__ = 'tb_users_other'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), unique=True)
    email2 = Column(BINARY, nullable=False)
    email2_mask = Column(Text, nullable=False)
    name = Column(Text, nullable=False, index=True)
    allow_ip = Column(JSON, nullable=False)
    deny_ip = Column(JSON, nullable=False)
    acl_serial = Column(BINARY, default=b'\0\0\0\0')
    protect = Column(Boolean, nullable=False, index=True)


class TB_USERS_LOGIN_FAIL(Base):
    __tablename__ = 'tb_users_login_fail'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    ip = Column(Text, nullable=False)
    count = Column(Integer, nullable=False)
    time = Column(Float, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'ip', name='unique_userid_ip'),)


class TB_USERS_LOCK(Base):
    __tablename__ = 'tb_users_lock'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    ip = Column(Text, nullable=False)
    time = Column(Float, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'ip', name='unique_userid_ip'),)


class TB_USERS_SESSION(Base):
    __tablename__ = 'tb_users_session'
    id = Column(Uuid, default=uuid7, primary_key=True)
    session_id = Column(Uuid, default=uuid4, unique=True)
    session_token = Column(JSON, nullable=False)
    session_data_key = Column(JSON, nullable=False)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    ip = Column(Text, nullable=False)
    login_time = Column(Float, nullable=False)
    refresh_time = Column(Float, nullable=False, index=True)


class TB_USERS_HISTORY_LOGIN(Base):
    __tablename__ = 'tb_users_history_login'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    time = Column(Float, nullable=False)
    ip = Column(Text, nullable=False)
    result = Column(Integer, nullable=False)


class TB_USERS_HISTORY_PASSWD(Base):
    __tablename__ = 'tb_users_history_passwd'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    password = Column(BINARY, nullable=False)
    time = Column(Float, nullable=False)


class TB_USERS_HISTORY_CONFIG(Base):
    __tablename__ = 'tb_users_history_config'
    id = Column(Uuid, default=uuid7, primary_key=True)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    time = Column(Float, nullable=False)
    ip = Column(Text, nullable=False)
    email_mask = Column(Text)
    password = Column(Integer)
    email2_mask = Column(Text)
    name = Column(Text)
    allow_ip = Column(JSON)
    deny_ip = Column(JSON)
    protect = Column(Boolean)
    locked = Column(Boolean)


class TB_USERS_HISTORY_DELETE(Base):
    __tablename__ = 'tb_users_history_delete'
    id = Column(Uuid, default=uuid7, primary_key=True)
    email = Column(BINARY, index=True, nullable=False)
    email_mask = Column(Text, nullable=False)
    user_id = Column(Uuid, index=True, nullable=False)
    trashed_time = Column(Float, nullable=False)
    trashed_ip = Column(Text, nullable=False)
    deleted_time = Column(Float, index=True, nullable=False)
    deleted_by = Column(Text, nullable=False)


__all__ = [
    'TB_USERS_MAIN',
    'TB_USERS_OTHER',
    'TB_USERS_LOGIN_FAIL',
    'TB_USERS_LOCK',
    'TB_USERS_SESSION',
    'TB_USERS_HISTORY_LOGIN',
    'TB_USERS_HISTORY_PASSWD',
    'TB_USERS_HISTORY_CONFIG',
    'TB_USERS_HISTORY_DELETE',
]
