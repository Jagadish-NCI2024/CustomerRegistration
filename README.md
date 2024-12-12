# Customer Review and Registration System

A Flask-based web application for user registration, login, and role-based access control. This application includes features like password hashing, session management, SQL injection prevention, and optional CAPTCHA integration.

Github Link : https://github.com/Jagadish-NCI2024/UserRegistration/tree/master
Reference Link: https://github.com/kritimyantra/flask-authentication-system/tree/main
---

## Features

- **User Registration**
  - Secure password storage with bcrypt hashing.
  - Input validation to prevent SQL injection and malicious inputs.
  
- **User Login**
  - Role-based access control (e.g., Admin and User roles).
  - Session management with optional session timeout configuration.

- **Admin Dashboard**
  - Assign roles to users.
  - Delete users.

- **Security Features**
  - SQL injection prevention.
  - Content Security Policy (CSP) headers.
  - Optional CAPTCHA integration.
  - Secure cookies with `HttpOnly`, `Secure`, and `SameSite` attributes.

---

## Prerequisites

- Python 3.7+
- SQLite3

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Jagadish-NCI2024/UserRegistration.git
   cd UserRegistration
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```bash
   python app.py
   ```
   This will create the `database.db` file and set up the necessary tables.

---

## Configuration

1. Update the `app.secret_key` in `app.py` to a strong secret key:
   ```python
   app.secret_key = os.urandom(32)  # Replace this with a fixed secret key for production
   ```

2. (Optional) Configure session timeout in `app.py`:
   ```python
   from datetime import timedelta
   app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Adjust timeout as needed
   ```

3. (Optional) Integrate CAPTCHA by following [these steps](https://github.com/Jagadish-NCI2024/UserRegistration#integrating-captcha).

---

## Usage

1. Run the application:
   ```bash
   python app.py
   ```

2. Access the application in your browser at [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Routes

### Public Routes
- `/` - Home page.
- `/register` - User registration.
- `/login` - User login.

### Protected Routes
- `/dashboard` - User dashboard (requires login).
- `/admin_dashboard` - Admin dashboard (requires admin role).
- `/assign_role` - Assign roles to users (requires admin role).
- `/delete_user` - Delete users (requires admin role).
- `/delete_account` - Delete own account.

---

## Security Features

1. **Password Security**:
   - Passwords are hashed using `bcrypt`.

2. **SQL Injection Prevention**:
   - Parameterized queries are used for all database interactions.

3. **Session Security**:
   - Cookies are secured with `HttpOnly`, `Secure`, and `SameSite` attributes.
   - Session timeout can be configured.

4. **Input Validation**:
   - Input is sanitized using `escape` from `markupsafe`.
   - Suspicious patterns (e.g., SQL keywords) are logged and rejected.

5. **Content Security Policy**:
   - Configured headers to prevent clickjacking and other attacks.

---

## To-Do

- Add email verification during registration.
- Implement multi-factor authentication (MFA).
- Enhance the UI with a modern framework (e.g., Bootstrap).
- Add support for deployment using Docker.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contribution

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

---

## Author

**Jagadish**

Feel free to reach out for questions or suggestions!

