# Prerequisites
- Rust 1.70+ (install from https://rustup.rs/)
- PostgreSQL 12+
- Git

# Setup Instructions

## 1. Install Rust
If you haven't already installed Rust, run:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 2. Clone and Setup
```bash
cd DasiaAIO-Backend
cp .env.example .env
# Edit .env with your PostgreSQL connection string and Gmail credentials
```

## 3. Database Setup
Make sure PostgreSQL is running. Create a new database:
```postgresql
CREATE DATABASE guard_firearm_system;
```

Update the `DATABASE_URL` in your `.env` file with the correct PostgreSQL connection details.

## 4. Build and Run

### Docker (recommended)

```bash
docker compose up -d --build
curl http://localhost:5000/api/health
```

PowerShell health check:

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/health" -UseBasicParsing
```

### Development Mode (with auto-reload)
```bash
cargo install cargo-watch
cargo watch -q -c -w src/ -x 'run'
```

### Production Build
```bash
cargo build --release
./target/release/server
```

### Running Tests
```bash
cargo test
```

## Environment Variables
Create a `.env` file in the `DasiaAIO-Backend` directory:

```
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/guard_firearm_system
GMAIL_USER=your_email@gmail.com
GMAIL_PASSWORD=your_app_specific_password
ADMIN_CODE=122601
```

Note: `ADMIN_CODE` is retained for backward compatibility in configuration but public registration now only allows guard self-registration.

### Note on Gmail Password
For Gmail, you need to generate an "App Password":
1. Enable 2-Factor Authentication on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Select "Mail" and "Windows/Linux/Mac"
4. Generate and use the provided app password

## API Endpoints

### Authentication
- `POST /api/register` - Public guard self-registration (starts as pending approval)
- `POST /api/login` - Login user
- `POST /api/verify` - Verify email with code
- `POST /api/resend-code` - Resend verification code

### Users
- `GET /api/users` - Get all users
- `POST /api/users` - Create user via authenticated actor (hierarchical RBAC)
- `GET /api/user/:id` - Get user by ID
- `PUT /api/user/:id` - Update user
- `DELETE /api/user/:id` - Delete user

### RBAC Notes
- Role hierarchy: `superadmin > admin > supervisor > guard`
- `superadmin` can create `admin`, `supervisor`, `guard`
- `admin` can create `supervisor`, `guard`
- Guard self-registration is public, but requires admin/supervisor approval before login

### Firearms
- `POST /api/firearms` - Add firearm
- `GET /api/firearms` - Get all firearms
- `GET /api/firearms/:id` - Get firearm by ID
- `PUT /api/firearms/:id` - Update firearm
- `DELETE /api/firearms/:id` - Delete firearm

### Firearm Allocation
- `POST /api/firearm-allocation/issue` - Issue firearm
- `POST /api/firearm-allocation/return` - Return firearm
- `GET /api/guard-allocations/:guard_id` - Get allocations for a guard
- `GET /api/firearm-allocations/active` - Get all active allocations

### Guard Replacement
- `POST /api/guard-replacement/shifts` - Create shift
- `POST /api/guard-replacement/attendance/check-in` - Check in
- `POST /api/guard-replacement/attendance/check-out` - Check out
- `POST /api/guard-replacement/detect-no-shows` - Detect no-shows
- `POST /api/guard-replacement/request-replacement` - Request replacement
- `POST /api/guard-replacement/set-availability` - Set availability

### Health
- `GET /api/health` - Health check

## Project Structure
```
backend-rust/
├── src/
│   ├── main.rs           # Entry point
│   ├── config.rs         # Configuration
│   ├── db.rs             # Database setup and migrations
│   ├── error.rs          # Error handling
│   ├── models.rs         # Data models
│   ├── utils.rs          # Utility functions
│   ├── routes.rs         # Route definitions
│   └── handlers/         # Request handlers
│       ├── mod.rs
│       ├── auth.rs
│       ├── users.rs
│       ├── firearms.rs
│       ├── firearm_allocation.rs
│       ├── guard_replacement.rs
│       └── health.rs
├── Cargo.toml
├── Cargo.lock
├── .env.example
└── .gitignore
```

## Troubleshooting

### Connection refused
Make sure PostgreSQL is running on your system.

### Compilation errors
Ensure you have Rust 1.70+ installed:
```bash
rustup update
```

### Database migration issues
The migrations run automatically on startup. If you need to reset:
1. Drop the database: `DROP DATABASE guard_firearm_system;`
2. Create it again: `CREATE DATABASE guard_firearm_system;`
3. Restart the server

## Performance Tips
- Use connection pooling (default: 5 connections)
- Enable release mode for production
- Monitor database query performance with logging enabled

## Next Steps
1. Set up PostgreSQL and create the database
2. Configure environment variables in `.env`
3. Run `cargo run` to start the development server
4. Update your frontend to point to `http://localhost:5000` for API calls

## Validation Checklist

- `docker compose config -q` passes.
- `docker compose up -d` starts both database and backend containers.
- `GET /api/health` returns `{\"status\":\"ok\"}`.
