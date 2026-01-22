## Authentication (JWT Bearer)

### Overview

The backend uses **Bearer JWT** authentication:

- Clients send: `Authorization: Bearer <token>`
- Most routes are protected using `Depends(get_token_claims)`

Important:
- `JWT_SECRET` must be set explicitly (no auto-generation)
- Tenant comes from server configuration (`AUTH_TENANT` or stored user tenant)

### Endpoints

#### Signup

- `POST /auth/signup`
- Body: `{ "username": "...", "password": "..." }`

Creates a user in Postgres with an Argon2 password hash.

#### Login

- `POST /auth/login`
- Body: `{ "username": "...", "password": "..." }`

Returns a JWT token.

#### Validate Token

- `GET /auth/token`
- Header: `Authorization: Bearer <token>`

Returns token claims if valid.

### JWT claims

Issued tokens include (at minimum):

- `sub`: username
- `tenant`: tenant name
- `auth`: authentication details (server-defined)
- `iat`, `exp`, `iss`

