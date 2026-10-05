import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Request Data
    method = Column(String, nullable=False, index=True)
    url = Column(String, nullable=False)
    path = Column(String, nullable=False, index=True)
    query_params = Column(JSONB, default=dict)
    request_headers = Column(JSONB, default=dict)
    request_body = Column(String, nullable=True)
    
    # Response Data
    response_status = Column(Integer, nullable=True, index=True)
    response_headers = Column(JSONB, default=dict)
    response_body = Column(String, nullable=True)
    
    # Metadata
    source = Column(String, nullable=False, default="burp") # e.g., 'burp', 'extension'
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
