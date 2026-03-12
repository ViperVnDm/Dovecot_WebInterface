#!/usr/bin/env python3
"""CLI management tool for Dovecot Web Admin Console."""

import argparse
import asyncio
import getpass
import sys

from app.database import init_db, create_initial_admin, async_session, AdminUser
from app.core.security import hash_password
from sqlalchemy import select


async def cmd_init_db(args):
    """Initialize the database."""
    print("Initializing database...")
    await init_db()
    print("Database initialized successfully.")


async def cmd_create_admin(args):
    """Create an admin user."""
    username = args.username or input("Username: ")
    password = args.password or getpass.getpass("Password: ")
    email = args.email

    if len(password) < 8:
        print("Error: Password must be at least 8 characters")
        sys.exit(1)

    await init_db()

    async with async_session() as session:
        # Check if user exists
        result = await session.execute(
            select(AdminUser).where(AdminUser.username == username)
        )
        if result.scalar_one_or_none():
            print(f"Error: User '{username}' already exists")
            sys.exit(1)

        # Create user
        admin = AdminUser(
            username=username,
            password_hash=hash_password(password),
            email=email,
        )
        session.add(admin)
        await session.commit()
        print(f"Admin user '{username}' created successfully.")


async def cmd_list_admins(args):
    """List all admin users."""
    await init_db()

    async with async_session() as session:
        result = await session.execute(select(AdminUser))
        admins = result.scalars().all()

        if not admins:
            print("No admin users found.")
            return

        print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Active':<8} {'Last Login'}")
        print("-" * 80)
        for admin in admins:
            last_login = admin.last_login.strftime("%Y-%m-%d %H:%M") if admin.last_login else "Never"
            print(f"{admin.id:<5} {admin.username:<20} {admin.email or '':<30} {str(admin.is_active):<8} {last_login}")


async def cmd_delete_admin(args):
    """Delete an admin user."""
    await init_db()

    async with async_session() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.username == args.username)
        )
        admin = result.scalar_one_or_none()

        if not admin:
            print(f"Error: User '{args.username}' not found")
            sys.exit(1)

        if not args.yes:
            confirm = input(f"Delete user '{args.username}'? [y/N]: ")
            if confirm.lower() != "y":
                print("Cancelled.")
                return

        await session.delete(admin)
        await session.commit()
        print(f"Admin user '{args.username}' deleted.")


async def cmd_change_password(args):
    """Change an admin user's password."""
    password = args.password or getpass.getpass("New password: ")

    if len(password) < 8:
        print("Error: Password must be at least 8 characters")
        sys.exit(1)

    await init_db()

    async with async_session() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.username == args.username)
        )
        admin = result.scalar_one_or_none()

        if not admin:
            print(f"Error: User '{args.username}' not found")
            sys.exit(1)

        admin.password_hash = hash_password(password)
        await session.commit()
        print(f"Password changed for '{args.username}'.")


def main():
    parser = argparse.ArgumentParser(
        description="Dovecot Web Admin Console Management Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init-db
    init_parser = subparsers.add_parser("init-db", help="Initialize the database")
    init_parser.set_defaults(func=cmd_init_db)

    # create-admin
    create_parser = subparsers.add_parser("create-admin", help="Create an admin user")
    create_parser.add_argument("-u", "--username", help="Username")
    create_parser.add_argument("-p", "--password", help="Password")
    create_parser.add_argument("-e", "--email", help="Email address")
    create_parser.set_defaults(func=cmd_create_admin)

    # list-admins
    list_parser = subparsers.add_parser("list-admins", help="List admin users")
    list_parser.set_defaults(func=cmd_list_admins)

    # delete-admin
    delete_parser = subparsers.add_parser("delete-admin", help="Delete an admin user")
    delete_parser.add_argument("username", help="Username to delete")
    delete_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    delete_parser.set_defaults(func=cmd_delete_admin)

    # change-password
    passwd_parser = subparsers.add_parser("change-password", help="Change admin password")
    passwd_parser.add_argument("username", help="Username")
    passwd_parser.add_argument("-p", "--password", help="New password")
    passwd_parser.set_defaults(func=cmd_change_password)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
