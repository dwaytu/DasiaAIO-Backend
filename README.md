# SENTINEL Backend

Rust/Axum API service for SENTINEL, the DSIA security operations platform.

## Overview

This service provides authentication, role-based authorization, operational workflows, tracking intelligence, and audit/governance endpoints for Web, Desktop, and Android clients.

## Stack

- Rust (edition 2021)
- Axum
- SQLx
- PostgreSQL
- Tokio

## Prerequisites

- Rust stable toolchain
- PostgreSQL 14+
- OpenSSL-compatible build environment

## Configuration

Create a local environment file in `DasiaAIO-Backend/`.

Core runtime variables:

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/guard_firearm_system
JWT_SECRET=replace_with_strong_secret
ADMIN_CODE=replace_default_code
```

Optional mail variables (verification/reset flows):

```env
GMAIL_USER=your_email@gmail.com
GMAIL_PASSWORD=app_specific_password
```

## Security Hardening Behavior

When running in production (`APP_ENV=production` or `NODE_ENV=production`), startup enforces:

- strong `JWT_SECRET`
- non-default `ADMIN_CODE`
- explicit CORS origin configuration (`CORS_ORIGINS`/`CORS_ORIGIN`)

Security middleware includes standard response hardening headers and request-timeout protection.

## Run Locally

```bash
cargo run --bin server
```

Health checks:

- `GET /api/health`
- `GET /api/health/system`
- `GET /api/system/version`

## Test and Validate

```bash
cargo check
cargo test
```

## Docker Workflow

```bash
docker compose up -d --build
```

## API Domain Coverage

- Authentication and session lifecycle
- Role-based user and approval workflows
- Scheduling, attendance, and replacement workflows
- Firearm, permit, and armored vehicle operations
- Incident, support, and notifications workflows
- Live tracking, geofence events, and map data
- Audit and forensic visibility

## Role Model

Supported roles:

- `guard`
- `supervisor`
- `admin`
- `superadmin`

## Repository Links

- Root governance/release repo: https://github.com/dwaytu/Capstone-Main
- Frontend app repo: https://github.com/dwaytu/DasiaAIO-Frontend
- Project docs: https://dwaytu.github.io/Capstone-Main/
