# User Authentication and Role-Based Access Control System

## Overview
This project implements a user authentication system with Role-Based Access Control (RBAC) for managing access based on user roles. The system includes features such as user registration, login, and role assignment, with additional functionalities for handling failed login attempts and account lockouts.

The system defines three roles:
- **Admin**
- **User**
- **Moderator**

It also incorporates security measures like account lockout after multiple failed login attempts, and utilizes JWT (JSON Web Tokens) for secure authentication.

## Features
1. **Role-Based Access Control**: 
   - Admin: Full access to the system.
   - User: Limited access based on specific permissions.
   - Moderator: Intermediate access, with some administrative capabilities.
   
2. **Account Lockout Mechanism**:
   - Accounts are locked for 30 minutes after 5 failed login attempts.

3. **JWT Authentication**:
   - JWT tokens (access and refresh tokens) are used for user authentication.

4. **Custom User Model**:
   - Extends Django's built-in user model with additional fields for roles and login attempt tracking.

## Installation
### Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/role-based-access-control.git
   cd role-based-access-control
   ```
   
2. **Install the Required Dependencies**
  ```bash
  pip install -r requirements.txt
  ```
3. **Make Migrations**
  ```bash
  python manage.py makemigrations
```
4. **Migrate the Database**
```bash
python manage.py migrate
```
5. **Run the Development Server**
```bash
python manage.py runserver
```

## Test Directly with Postman (Deployed Version)

You can skip the local setup and directly test the system using the Postman collection and the live demo link:

### Postman API Documentation:
- [View Postman Collection](https://documenter.getpostman.com/view/26432004/2sAYBVhXRH)  
  **Note**: All endpoints are already included in this collection.

### Live Demo URL:
- [Deployed Application](https://vrv-backend-assignment.onrender.com)


---

### Steps:
1. **Import the Postman collection** using the provided link.
2. **Use the live demo URL** as the base URL for your requests.
3. **Authenticate** using the login endpoint to obtain JWT tokens.
4. **Access secured endpoints** by including the JWT token in the `Authorization` header.

---
### Endpoints Overview:
You can explore and test all the endpoints directly through the Postman collection:
- User Registration
- User Login
- Admin Access
- Moderator Access
- User Access

No additional setup is required. Simply follow the collection for detailed endpoint information and test cases.
