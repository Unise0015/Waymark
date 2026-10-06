from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.database import Base

class RequestChain(Base):
    __tablename__ = "request_chains"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    hypothesis = Column(Text, nullable=True)  # What the tester thinks might be vulnerable
    ai_analysis = Column(Text, nullable=True)  # AI's full chain analysis result
    severity = Column(String(50), nullable=True)  # AI-assessed severity
    verdict = Column(String(50), nullable=True)  # confirmed / partial / failed / inconclusive
    status = Column(String(50), default="draft")  # draft / analyzed
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    steps = relationship("RequestChainStep", back_populates="chain", order_by="RequestChainStep.step_order", cascade="all, delete-orphan")

class RequestChainStep(Base):
    __tablename__ = "request_chain_steps"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    chain_id = Column(UUID(as_uuid=True), ForeignKey("request_chains.id", ondelete="CASCADE"), nullable=False)
    traffic_log_id = Column(UUID(as_uuid=True), ForeignKey("traffic_logs.id", ondelete="SET NULL"), nullable=True)
    step_order = Column(Integer, nullable=False)
    note = Column(Text, nullable=True)  # Tester's note for this step
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    chain = relationship("RequestChain", back_populates="steps")
    traffic_log = relationship("TrafficLog")
