# SENTINEL Backend

Rust + Axum API server for the SENTINEL security operations platform.

## Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- Git

## Setup

```bash
cd DasiaAIO-Backend
cp .env.example .env
```

Update `.env` with your database and mail configuration.

## Core Environment Variables

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/guard_firearm_system
GMAIL_USER=your_email@gmail.com
GMAIL_PASSWORD=your_app_specific_password
ADMIN_CODE=122601
```

Production hardening note:

- When `APP_ENV=production` (or `NODE_ENV=production`), backend startup now validates critical settings and fails fast if unsafe:
	- `JWT_SECRET` must be set to a strong secret (32+ chars)
	- `ADMIN_CODE` must not use default `122601`
	- `CORS_ORIGINS` or `CORS_ORIGIN` must be configured

`ADMIN_CODE` remains for compatibility, while public registration flow is guard self-registration with approval.

## Run Options

### Docker (recommended)

```bash
docker compose up -d --build
```

Health check:

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/health" -UseBasicParsing
```

### Local Development

```bash
cargo run
```

Auto-reload mode:

```bash
cargo install cargo-watch
cargo watch -q -c -w src/ -x 'run'
```

### Tests

```bash
cargo test
```

## Key API Areas

- Authentication and verification
- Hierarchical RBAC user management
- Firearm inventory and allocation
- Guard replacement and attendance
- Health and operational endpoints

Primary health endpoint:

- `GET /api/health`

## Role Hierarchy

- `superadmin > admin > supervisor > guard`
- Guard self-registration requires approval before login access.

## Project Structure

```text
DasiaAIO-Backend/
	src/
		handlers/
		middleware/
		services/
		main.rs
		routes.rs
		models.rs
		db.rs
	migrations/
	Dockerfile
	docker-compose.yml
	Cargo.toml
```

## Validation Checklist

- `docker compose config -q` passes.
- `docker compose up -d --build` starts required services.
- `GET /api/health` returns a healthy status payload.
