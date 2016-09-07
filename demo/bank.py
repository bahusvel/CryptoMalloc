details = open("merged.csv", mode='r')
account_map = {}
for entry in details.readlines():
	parts = entry.strip("\r").split(",")
	account_map[parts[0]] = parts[1]
while True:
	email = input("Please enter email:")
	if email in account_map:
		print(account_map[email])
	else:
		print("Sorry this email was not found")
