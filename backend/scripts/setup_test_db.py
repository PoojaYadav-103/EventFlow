import psycopg

def setup_test_db():
    conn = psycopg.connect("postgresql://postgres:postgres@localhost:5432/postgres", autocommit=True)
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname='eventflow_test'")
        if not cur.fetchone():
            cur.execute("CREATE DATABASE eventflow_test")
            print("Database eventflow_test created.")
        else:
            print("Database eventflow_test already exists.")
    conn.close()

if __name__ == "__main__":
    setup_test_db()
