"""Run once after the Supabase schema is applied: python -m scripts.seed_admin
Creates the default admin user (must_change_password=True) from .env values.
Safe to re-run - it's a no-op if the admin email already exists.
"""

import asyncio

from sqlalchemy import select

from app.auth.security import hash_password
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import User


async def main() -> None:
    async with SessionLocal() as session:
        result = await session.execute(select(User).where(User.email == settings.default_admin_email))
        if result.scalar_one_or_none() is not None:
            print(f"Admin '{settings.default_admin_email}' already exists - skipping.")
            return
        user = User(
            email=settings.default_admin_email,
            password_hash=hash_password(settings.default_admin_password),
            role="admin",
            must_change_password=True,
        )
        session.add(user)
        await session.commit()
        print(f"Seeded admin '{settings.default_admin_email}'.")
        print("Default password is set in .env (DEFAULT_ADMIN_PASSWORD) - log in once and change it immediately.")


if __name__ == "__main__":
    asyncio.run(main())
