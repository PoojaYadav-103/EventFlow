from alembic import command
from alembic.config import Config

alembic_cfg = Config("backend/alembic.ini")
alembic_cfg.set_main_option("script_location", "backend/alembic")
alembic_cfg.set_main_option("sqlalchemy.url", "postgresql+psycopg://postgres:postgres@localhost:5432/eventflow_test")
command.upgrade(alembic_cfg, "head")
print("eventflow_test upgraded to head successfully!")
