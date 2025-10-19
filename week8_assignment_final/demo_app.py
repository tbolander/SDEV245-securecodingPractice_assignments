import os

# demo AWS secret key (random gen, not real)
AWS_ACCESS_KEY = "AKIA7ZQ9LMNO13XY45PQ"

# demo Stripe API key for test
STRIPE_SECRET_KEY = "sk_live_" + "pM3r2N8xBvT4zQaR1yHjKfWd"

# demo slack bot tokens
bot_token = "xoxb-85274619203-94738261048-kP3mN7vQ2wR8xL4jT9sY6hZc"
user_access = "xoxp-85274619203-94738261048-fG8dK3pX7nM2qW5vB9cH4tYz"

# demo heroku API key
HEROKU_KEY = "3f7a2b9c-5d8e-4a1f-9c6b-2e8d5a7f3b1c"

# demo mailgun API key
mailgun_API_key = "key-8d7f3a2c9b5e1f4d6a8b2c3d5e7f9a0b"

# normal config (should not be detected)
username = "student_user"
db_port = 5432
debug_mode = True

def setup_payment():
    # demo stripe integration
    headers = {"Authorization": f"Token {STRIPE_KEY}"}
    print("Payment gateway connected")

def send_slack_msg(message):
    # sends "notification" to slack
    print(f"Sending to slack: {message}")

def main():
    print("Demo application starting...")
    setup_payment()
    send_slack_msg("demo started successfully")

if __name__ == "__main__":
    main()
