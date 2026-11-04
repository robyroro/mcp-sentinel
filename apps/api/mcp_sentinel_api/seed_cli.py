from .database import Base, SessionLocal, engine
from .seed import seed_database


def main() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as database:
        seed_database(database, force=True)
        print("Synthetic demo dataset seeded.")


if __name__ == "__main__":
    main()
