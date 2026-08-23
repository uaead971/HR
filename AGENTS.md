# Repository Guidelines

## Project Structure & Module Organization
- **`./server.py`**: A dependency-free Python backend using standard libraries (`http.server`, `sqlite3`). It manages all business logic, RBAC enforcement, and API endpoints.
- **Frontend**: A vanilla JavaScript and CSS frontend (`./app.js`, `./styles.css`, `./index.html`) designed for RTL/Arabic users.
- **`./data/`**: Stores the SQLite database (`./data/hr.sqlite3`).
- **`./schema.sql`**: Defines the database schema, including audit logs and permissions.
- **`./tests/`**: Contains integration tests (`./tests/test_api.py`) that perform end-to-end verification using a temporary server instance.

## Build, Test, and Development Commands
- **Start Development Server**: `python3 ./server.py --host 127.0.0.1 --port 8765`
- **Run All Tests**: `python3 -m unittest -v tests.test_api`
- **Run Specific Test**: `python3 -m unittest -v tests.test_api.HRAPIEndToEndTests.test_name`
- **Database Setup**: The server automatically initializes the database from `./schema.sql` if it does not exist.

## Coding Style & Naming Conventions
- **Backend**: Python code follows PEP 8 conventions. Use Type Hints and `pathlib.Path` for file operations. Business logic is grouped into functional blocks (Security, People, Time, Payroll).
- **Frontend**: Maintain RTL compatibility and Arabic language support. Avoid external frameworks; stick to standard Web APIs.
- **Security**: All state-changing operations must include CSRF tokens. Sensitive data (passwords, SMTP credentials) must be hashed or masked.

## Testing Guidelines
- **Framework**: `unittest`.
- **Approach**: Integration testing is preferred. Tests should verify status codes, JSON responses, and database state changes.
- **Requirements**: New features must include corresponding test cases in `./tests/test_api.py` covering success and failure paths (e.g., unauthorized access).

## Agent Instructions
- Follow the established RBAC model defined in `PERMISSION_CATALOG` within `./server.py`.
- Ensure all API responses return proper HTTP status codes.
- Validate file uploads (MIME type and size) both on the client and server.
