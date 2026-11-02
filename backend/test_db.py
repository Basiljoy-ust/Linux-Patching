from database import get_connection


def main():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT NOW(), current_database(), current_user;"
            )

            result = cursor.fetchone()

            print("Database connection successful")
            print("Database time:", result[0])
            print("Database:", result[1])
            print("User:", result[2])

    finally:
        connection.close()


if __name__ == "__main__":
    main()
