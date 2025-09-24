# secured_data_application_M4

A short midterm application of both SHA256 hashing and AES encryption/decryption. The program can handle both plain text messages and files. After completing encryption and decryption, it verifies the data hasn't been modified by comparing hashes.

***Requirements:***
1. Python 3 or newer (preferably the latest version of Python.)
2. pycryptodome library (in powershell, use 'pip install pycryptodome')

***How To Run:***
1. Open Powershell in the project folder by right clicking anywhere in the program folder, and then clicking 'Open in Terminal'. Alternatively, double click 'secured_data_application_M4' from the program folder.
2. Follow the prompts. You can type 'message' to enter a short text message for demonstration, or 'file' to type the path of a plain text file.
3. Enter a password for encryption, which is used to generate the AES key.

The program will show the original SHA-256 hash, encrypt and output AES details, decrypt the data, and compare hashes to verify integrity. If using 'message', it will print the recovered message. For files, it will print that the decrypted file matches the original (useful for live demonstration purposes).

***How My Project Upholds CIA (Confidentiality, Integrity, and Availability):***

Confidentiality - My project uses AES encryption in GCM mode to ensure the data is scrambled and can only be decrypted with the correct password.

Integrity - I use SHA256 before and after encryption/decryption. If the hashes don't match, that means the original data has been altered. GCM adds an auth tag as well that checks for tampering.

Availability - My project can take both plain text user input and files, it runs locally, and is simple to run over and over again. This ensures that the information is still available and usable if needed in the future.

***The Role of Entropy and Key Generation in my Project***

A random salt and nonce are generated on each run. This randomness makes it hard for any attackers to reuse old outputs or guess keys. The password is also stretched into a secure key with PBKDF2 and 50k iterations, slowing down brute-force attacks to ensure the key has enough strength for AES.