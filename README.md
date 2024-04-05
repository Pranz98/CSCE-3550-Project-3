CSCE 3550 Project 3

JWKS Server: Enhancing Security and User Management

Objective : 
The objective of this project is to further enhance the security and functionality of the JWKS server by implementing AES encryption for private keys, adding user registration capabilities, logging authentication requests, and optionally introducing a rate limiter to control request frequency.

Background : 
As cybersecurity threats evolve, it's crucial to continuously improve the security and robustness of authentication systems. This project focuses on adding layers of security to the JWKS server by encrypting sensitive data, managing user registrations, and monitoring authentication requests. Additionally, implementing the optional rate limiter can prevent abuse and protect the server from potential DoS attacks.

Note: In a "real system", a random initialization vector (IV) would also be included for each encryption, enhancing security by providing variability and unpredictability to the encryption process.

Requirements : 
AES Encryption of Private Keys
Encrypt private keys in the database using symmetric AES encryption.
Use a key provided from the environment variable named NOT_MY_KEY for encryption and decryption.
Ensure that the encryption process is secure and that the key is never exposed.
User Registration
Create a users table in the database with appropriate fields for storing user information and hashed passwords.
Implement a POST:/register endpoint that:
Accepts user registration details in request body using JSON format.
Generates a secure password for the user using UUIDv4.
Returns the password to the user in JSON format.
Hashes the password using the secure password hashing algorithm Argon2.
Stores the user details and hashed password in the users table.
Logging Authentication Requests
Create a database table auth_logs to log authentication requests.
For each POST:/auth request, log the following details into the DB table auth_logs:
Request IP address.
Timestamp of the request.
User ID of the username.
Rate Limiter (Optional)
Implement a time-window rate limiter for the POST:/auth endpoint.
Limit requests to 10 requests per second.
Return a 429 Too Many Requests for requests over the limit.
Log only requests that succeed to the authentication logging table.

Expected Outcome : 
By the end of the project, the JWKS server should have enhanced security through AES encryption, the ability to register users and store their hashed passwords, a logging mechanism for authentication requests, and an optional rate limiter to control request frequency.

