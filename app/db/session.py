"""
Database session management for the CaaS application.

This module provides database connection and session management using SQLAlchemy.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator
import os

from app.config import settings
from app.models.database import Base


# Create database engine
def get_engine():
    """
    Create and configure the database engine.

    For SQLite, we use StaticPool to ensure the database connection
    persists across requests in development.
    """
    # Ensure data directory exists
    db_path = settings.database_url.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    # Create engine with appropriate settings
    if settings.database_url.startswith("sqlite"):
        engine = create_engine(
            settings.database_url,
            connect_args={"check_same_thread": False},  # Needed for SQLite
            poolclass=StaticPool,
            echo=settings.database_echo,
        )

        # Enable foreign keys for SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    else:
        engine = create_engine(
            settings.database_url,
            echo=settings.database_echo,
        )

    return engine


# Create engine instance
engine = get_engine()

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Initialize the database by creating all tables.

    This function should be called during application startup.
    """
    Base.metadata.create_all(bind=engine)
    print(f"[OK] Database initialized successfully at: {settings.database_url}")


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for getting database sessions in FastAPI endpoints.

    Yields:
        Session: SQLAlchemy database session

    Example:
        @app.get("/users")
        def get_users(db: Session = Depends(get_db)):
            users = db.query(User).all()
            return users
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def drop_all_tables():
    """
    Drop all database tables.

    WARNING: This will delete all data! Only use for testing or reset.
    """
    Base.metadata.drop_all(bind=engine)
    print("[WARNING] All tables dropped successfully")


def reset_db():
    """
    Reset the database by dropping and recreating all tables.

    WARNING: This will delete all data! Only use for testing or reset.
    """
    drop_all_tables()
    init_db()
    print("[RESET] Database reset complete")
