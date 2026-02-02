"""
Database seeding script for creating initial test data.

This module provides functions to populate the database with test users
for development and demonstration purposes.
"""

from sqlalchemy.orm import Session
import bcrypt

from app.models.database import User
from app.db.session import SessionLocal, init_db


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    # Encode password to bytes and hash it
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def create_test_users(db: Session):
    """
    Create test users for development.

    Args:
        db: Database session
    """
    test_users = [
        {
            "username": "admin",
            "email": "admin@caas.local",
            "password": "Admin123!",
        },
        {
            "username": "testuser",
            "email": "test@caas.local",
            "password": "Test123!",
        },
        {
            "username": "demo",
            "email": "demo@caas.local",
            "password": "Demo123!",
        },
    ]

    created_users = []

    for user_data in test_users:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.username == user_data["username"]) |
            (User.email == user_data["email"])
        ).first()

        if existing_user:
            print(f"[>] User '{user_data['username']}' already exists, skipping...")
            continue

        # Create new user
        new_user = User(
            username=user_data["username"],
            email=user_data["email"],
            password_hash=hash_password(user_data["password"]),
            is_active=True,
        )

        db.add(new_user)
        created_users.append(user_data["username"])

    db.commit()

    if created_users:
        print(f"[OK] Created {len(created_users)} test user(s): {', '.join(created_users)}")
    else:
        print("[i] No new users created (all users already exist)")

    return created_users


def seed_database():
    """
    Main function to seed the database with initial data.
    """
    print("[*] Starting database seeding...")

    # Initialize database (create tables if they don't exist)
    init_db()

    # Create session
    db = SessionLocal()

    try:
        # Create test users
        create_test_users(db)

        print("[OK] Database seeding completed successfully!")
        print("\n[INFO] Test Users Credentials:")
        print("   Username: admin    | Password: Admin123!")
        print("   Username: testuser | Password: Test123!")
        print("   Username: demo     | Password: Demo123!")

    except Exception as e:
        print(f"[ERROR] Error during database seeding: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
