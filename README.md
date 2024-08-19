# Passkeys Auth Server

Auth Service with Passkey Support using Express.js

This project demonstrates an implementation of an authentication service using Express.js that supports both traditional passwords and the new WebAuthn Passkey API.

## Key Features:

- Express.js: Leverages Express.js framework for building the server-side API.
- Password Support: Includes a standard password-based authentication mechanism for compatibility.
- Passkey Integration: Implements the WebAuthn Passkey API for secure and convenient login experiences.
- Coexistence: Maintains both password and passkey functionalities, allowing users to choose their preferred method.

## Environment Variables:

- MONGODB_URL: Connection string for your MongoDB database. (e.g., mongodb://127.0.0.1:27017/rest-api-nodejs-mongodb)
- JWT_SECRET: A secret string used for signing JSON Web Tokens (JWTs).
- JWT_TIMEOUT_DURATION: Duration (e.g., "2 hours") for which a JWT remains valid. Refer to https://github.com/auth0/node-jsonwebtoken for details.
- EMAIL_SMTP_HOST: Hostname of your SMTP server for sending emails.
- EMAIL_SMTP_PORT: Port number used by your SMTP server.
- EMAIL_SMTP_USERNAME: Username for authentication with your SMTP server.
- EMAIL_SMTP_PASSWORD: Password for authentication with your SMTP server.
- EMAIL_SMTP_SECURE: Boolean value indicating secure connection (true for port 465, false for others).
- PASSKEY_RPID: Your domain name used as the Relying Party Identifier (RPID) for passkey authentication. (e.g., google.com)
- PASSKEY_ORIGINS: Space-separated list of origins (URLs) allowed to use passkeys with this service. (e.g., http://localhost:3000)

## Setup:

1. Installation: Run `npm install` in the project directory to install required dependencies.
2. Start Server: Run `npm start` to start the server.

## Additional Resources:

1. Android Sample: A sample Android application demonstrating passkey usage is available at https://github.com/bgaurav7/passkeys-auth-android.
2. Simpler Passkey Implementation: For a basic understanding of passkeys, refer to https://github.com/bgaurav7/passkeys-auth.

Note: This project provides a starting point for implementing an authentication service with passkey support. You might need to modify and extend it based on your specific requirements and security considerations.