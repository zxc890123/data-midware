from sqlalchemy import Column, Uuid, Text, Integer, Boolean, Float, ForeignKey

from uuid_extensions import uuid7

from ..._share.db import Base


class TB_APPS_MFA_MAIN(Base):
    __tablename__ = 'tb_apps_mfa_main'
    id = Column(Uuid, primary_key=True, default=uuid7)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), index=True)
    name = Column(Text, nullable=False)
    comment = Column(Text)
    secret = Column(Text, nullable=False)
    position = Column(Integer, nullable=False)
    algorithm = Column(Text, nullable=False)
    interval = Column(Integer, nullable=False)
    digits = Column(Integer, nullable=False)
    created_time = Column(Float, nullable=False)
    updated_time = Column(Float, nullable=False)


class TB_APPS_MFA_OTHER(Base):
    __tablename__ = 'tb_apps_mfa_other'
    id = Column(Uuid, primary_key=True, default=uuid7)
    user_id = Column(Uuid, ForeignKey('tb_users_main.user_id', onupdate='CASCADE', ondelete='CASCADE'), unique=True)
    protect = Column(Boolean, default=False, nullable=False)


__all__ = ['TB_APPS_MFA_MAIN', 'TB_APPS_MFA_OTHER']
