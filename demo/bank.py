from simplecrypt import decrypt
details = open("details.enc", mode='rb')
plaintext = str(decrypt('password', details.read()))
entries = plaintext.split("\\n")
account_map = {}
for entry in entries:
	parts = entry.strip("\\r").split(",")
	account_map[parts[0]] = parts[1]
print(account_map)
while True:
	email = input("Please enter email:")
	if email in account_map:
		print(account_map[email])
	else:
		print("Sorry this email was not found")
