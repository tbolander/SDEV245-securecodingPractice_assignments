# owaspVulnerabilityFix.py

***(1). Broken Access Control***

>Flaw: The sample code let anyone request another user's profile by just changing the userId in the URL, leaving the possibility for private data to be exposed.
>
>>My Solution: My fix is the view_profile() function, which checks that the logged in user matches the ID, unless the user is an admin. If not, it blocks access, preventing someone from pulling other user profiles.
[OWASP Broken Access Control](owasp.org/Top10/A01_2021-Broken_Access_Control/)

***(2). Account Access Permissions***

>Flaw: The sample account function doesn't check permissions at all. 
>
>>My Solution: added a view_account() function to make sure the requester is equal to the same user or an admin before returning account data. If not, returns a forbidden error to lock down account details.
[OWASP Broken Access Control (continued)](owasp.org/Top10/A01_2021-Broken_Access_Control/)

***(3). Weak MD5 Hash***

>Flaw: Sample code Uses MD5 for password hashing.
>
>>My Solution: created a make_password_hash() function that uses bcrypt with 12 rounds of salting. Ensures each hash is unique, making it time consuming to brute force. This makes any password dumps a lot harder to use.
[OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

***(4). Weak SHA1 Hash***

>Flaw: Sample SHA1 version has the same weakness as MD5 in previous sample code.
>
>>My Solution: simple_password_hash() function that swaps SHA1 for bcrypt. Although a very simple fix, it is still way more secure as bcrypt automatically salts passwords.
[OWASP Cryptographic Failures (continued)](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

***(5). SQLi Injection***

>Flaw: A classic injection vulnerability, as the sample code directly built the SQL query with user input.
>
>>My Solution: fetch_user_by_name() function that uses a prepared statement placeholder to stop attackers from injecting SQL code into the query.
[OWASP Injection](https://owasp.org/Top10/A03_2021-Injection/)

***(6). NoSQL Injection***

>Flaw: Dropped raw query parameters into MongoDB that can be abused with some special operators to bypass checks.
>
>>My Solution: read_user() function that strips whitespace, checks length, and runs a regex to only allow safe characters. This ensures only cleaned usernames reach the query.
[OWASP Injection](https://owasp.org/Top10/A03_2021-Injection/)

***(7). Password Reset Vulnerability***

>Flaw: Sample lets anyone reset a password if they knew the email. 
>
>>My Solution: Two functions, request_reset_link() generates a reset token, hashes with bcrypt, and stores it with a expiry timestamp. finish_reset() then checks the submitted token against stored hashes, verifies expiry, and finally updates the password. Resets are mostly safe because only users with email account access can complete the full process.
[OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

***(8). Software and Data Integrity Failures***

>Flaw: The sample script tag pulls code from a CDN without any checks. This could be a problem if the CDN was compromised.
>
>>My Solution: Used SRI (SHA-384) and crossorigin="anonymous". Included make_sri_sha384() to only run the exact library version I trust.
[OWASP Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

***(9). Server Side Request Forgery***

>Flaw: Sample code lets users enter any URL and the server fetched it, which can be used to access local files or could hit interal networks.
>
>>My Solution: pull_url() function with url_is_safe() helper function. These check the scheme, verify the hostname against an allow list, and doesn't follow redirects.
[OWASP SSRF](https://owasp.org/Top10/A10_2021-Server_Side_Request_Forgery/)

***(10). Identification and Authentication Failures***

>Flaw: Sample login check just compares the input password directly to the stored plaintext password, meaning no hashing.
>
>>My Solution: login_user() function that verifies passwords using bcrypt, keeps count of failed attempts, and locks the account after 5 failures for 15 minutes, resetting the counter on success. This helps protect account integrity.
[OWASP Identification & Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)