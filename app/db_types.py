"""Column types that use the best native PostgreSQL type and degrade gracefully on SQLite (tests)."""
from datetime import timezone

from sqlalchemy import JSON, BigInteger, DateTime, Integer, String, TypeDecorator
from sqlalchemy.dialects.postgresql import INET, JSONB

# BIGINT identity on PostgreSQL; plain INTEGER on SQLite (needed for its rowid auto-increment).
BigInt = BigInteger().with_variant(Integer, "sqlite")
# JSONB on PostgreSQL (indexable, binary); generic JSON elsewhere.
JSONType = JSON().with_variant(JSONB, "postgresql")


class UTCDateTime(TypeDecorator):
    """timestamptz on PostgreSQL. Always returns timezone-aware UTC datetimes; refuses naive ones.

    Storing naive datetimes is the classic source of 'events are off by 5 hours' bugs, so it is an error here.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetime rejected: use timezone-aware UTC (see models.utcnow).")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:  # SQLite drops tzinfo; everything we store is UTC
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class IPAddress(TypeDecorator):
    """inet on PostgreSQL (validated, supports subnet operators); string elsewhere. Always a str in Python."""

    impl = String(45)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(INET())
        return dialect.type_descriptor(String(45))

    def process_bind_param(self, value, dialect):
        return None if value is None else str(value)

    def process_result_value(self, value, dialect):
        return None if value is None else str(value)
