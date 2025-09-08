# a basic iteration of role-based access control. For the CIA triad, this script demonstrates the "confidentiality" pillar.
# only authorized users can log in. Certain roles are restricted to certain actions. :)

users = {"admin": "admin", "user": "user"}
actions = {"stats": "admin", "home": "user"}

def check_access(user_role, action):
    return user_role == actions.get(action)

def show_stats():
    print("System stats: 1 active users, 0 errors")

def show_home():
    print("Welcome! You have 1 new message")

username = input("Username: ")
if username not in users:
    print("Invalid user. Please try again.")
    exit()

role = users[username]
print(f"Logged in as {role}")

action = input("Action (stats/home): ")
if action not in actions:
    print("Invalid action")
    exit()

if not check_access(role, action):
    print("Access denied")
    exit()

if action == "stats":
    show_stats()
else:
    show_home()