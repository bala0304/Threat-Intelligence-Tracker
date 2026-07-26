"""Base class for threat intelligence feed ingestors."""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.database.models import IngestionLog


class BaseFeedIngestor(ABC):
    """Base class for threat feed ingestors."""

    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.feed_source = self.__class__.__name__
        self.start_time = None
        self.end_time = None
        self.records_ingested = 0
        self.records_updated = 0
        self.errors = []

    @abstractmethod
    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch raw data from feed source."""
        pass

    @abstractmethod
    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse raw data into standardized format."""
        pass

    @abstractmethod
    def ingest(self) -> Dict[str, Any]:
        """Ingest data into database."""
        pass

    def log_ingestion(self, status: str = "success"):
        """Log ingestion activity."""
        log_entry = IngestionLog(
            feed_source=self.feed_source,
            feed_type=self.feed_source.lower(),
            ingestion_start=self.start_time,
            ingestion_end=self.end_time or datetime.utcnow(),
            records_ingested=self.records_ingested,
            records_updated=self.records_updated,
            errors_encountered=len(self.errors),
            status=status,
            error_details="\n".join(self.errors) if self.errors else None,
        )
        try:
            self.db_session.add(log_entry)
            self.db_session.commit()
        except SQLAlchemyError as exc:
            self.db_session.rollback()
            logger.warning(f"Failed to write {self.feed_source} ingestion log: {exc}")
            return

        logger.info(
            f"{self.feed_source} ingestion {status}. "
            f"Ingested: {self.records_ingested}, Updated: {self.records_updated}"
        )
