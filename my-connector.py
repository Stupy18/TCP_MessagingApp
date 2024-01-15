import mysql.connector
mydb = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Stupy_Mihai',
    port='3306',
    database='messagingapp'
)
mycursor = mydb.cursor()

# Selecting and printing existing users
mycursor.execute('SELECT * FROM users')
users = mycursor.fetchall()
for user in users:
    print(user)

# New users to be added
new_users = [
    (2, "username1", "password12"),
    (3, "username2", "password1")
]

# Inserting new users
# for user in new_users:
#     sql = "INSERT INTO users (user_id, username, password) VALUES (%s, %s, %s)"
#     mycursor.execute(sql, user)

# Committing the changes
mydb.commit()

# Closing the cursor and connection
mycursor.close()
mydb.close()
