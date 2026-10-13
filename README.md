# Zero Trust Network Implementation

CyberDome is a local zero-trust access-control prototype. It combines OIDC authentication, LDAP-backed identities, contextual trust scoring, role-based policy thresholds, a peer-to-peer decision pipeline, and a Flask Web UI.

See [How CyberDome Works](docs/how-it-works.md) for the architecture, authentication and access-decision flows, trust calculation, persisted state, and current prototype limitations.

See the [Changelog](docs/changelog.md) for a dated record of implementation and setup changes.

## Project Overview

The implementation will rely on the following components:

- **Trust Engine**: A trust engine will be implemented to calculate the trust scores of different subjects accessing various resources. It will assess user behavior, device health, and other factors to determine trust levels.

- **Policy Engine**: A policy engine component will enforce access control policies based on trust scores and other parameters. It ensures that users and devices can only access resources for which they have the necessary permissions.

- **Access Proxy**: An access proxy will act as an intermediary between users/devices and resources. It will enforce policies, authenticate users, and log access attempts.

## Technologies Used

The project will utilize various technologies, including:

- Trust Engine: Python, Machine Learning Algorithms, Markov chains
- Policy Engine: Python
- Access Proxy: Nginx, OAuth, Flask framework

## Getting Started

### Local setup

Create a Python environment and install the application dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create your settings file from the template, then fill in the values. The comments in the file explain each one:

```bash
cp .env.example .env
```

`.env` holds secrets and is git-ignored. The Web UI reads it at startup (see `cyberdome/settings.py`) and stops with a clear message if a required value is missing.

Start Colima if it is not already running, then start the local Postgres, OpenLDAP, phpLDAPadmin, and Keycloak services:

```bash
colima start
docker context use colima
docker compose up -d --build
docker compose ps
```

The local development endpoints and credentials are:

| Service | URL or address | Credentials |
| --- | --- | --- |
| Keycloak | `http://localhost:8080/auth` | `admin` / `admin` |
| phpLDAPadmin | `http://localhost:8081` | `cn=admin,dc=leonet,dc=cns` / `admin_pass` |
| LDAP | `ldap://localhost:389` | `cn=admin,dc=leonet,dc=cns` / `admin_pass` |
| Web UI demo user | Keycloak login | `demo` / `demo` |
| LDAP test user | Keycloak login | `alice` / `alice` |

These credentials are for local development only. The imported `myrealm` realm contains the `ZeroTrustPlatform` client expected by the application. The `demo` user has the `Approver` client role. LDAP is configured as a Keycloak user federation provider; assign an application client role to LDAP users in Keycloak before using them in the Web UI.

Start the Trust Engine, Policy Engine, and Access Proxy together:

```bash
./scripts/runAll.sh
```

In a second terminal, start the Web UI:

```bash
source venv/bin/activate
./scripts/runWebUI.sh
```

The scripts in `scripts/` work from any folder. Open `http://localhost:5000`. Stop the Python services with `Ctrl+C` (the engines can take 10 to 20 seconds to stop), then stop the identity stack with:

```bash
docker compose down
```

To delete all local identity data and recreate the seeded environment on the next start, use `docker compose down -v`.

## Contribution Guidelines

Contributions are welcome! Please follow these guidelines when contributing to the project:

- Fork the repository and create a new branch for your feature/bugfix.
- Ensure your code follows the project's coding standards.
- Submit a pull request, clearly describing the changes you made.

## License
