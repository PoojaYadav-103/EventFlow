import os
import sys

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

TEST_DB_FILE = os.path.join(backend_dir, "test_eventflow.db")
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"

# Configure environment for tests
os.environ["CELERY_TASK_ALWAYS_EAGER"] = "True"
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["ALLOW_INTERNAL_NETWORKS"] = "True"
os.environ["ENCRYPTION_KEY"] = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="

from app.core.config import settings
settings.ENCRYPTION_KEY = "yU8qY9hWcKjP3vF7rB2sT6xZ1aE4dG5hI7kL9mN2pQ4="

import app.database.session as db_session_module

# Dispose the original engine created on import and point the global session
# and engine to our test database before importing app modules.
db_session_module.engine.dispose()

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=NullPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

db_session_module.engine = test_engine
db_session_module.SessionLocal = TestSessionLocal

from app.database.session import Base, get_db
from app.main import app
from app.workers.celery_app import celery_app

# Configure Celery eager with in-memory broker
celery_app.conf.update(
    broker_url="memory://",
    result_backend="cache+memory://",
    task_always_eager=True,
    task_eager_propagates=True,
)


def _remove_test_db_file():
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except OSError:
            pass


@pytest.fixture(scope="function")
def db_session():
    test_engine.dispose()
    _remove_test_db_file()
    Base.metadata.create_all(bind=test_engine)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()
        _remove_test_db_file()


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
