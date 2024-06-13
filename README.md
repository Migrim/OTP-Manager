# OTP-Manager

OTP-Manager is a secure, easy-to-use tool designed to manage one-time passwords (OTP) for various applications. It supports TOTP (Time-based One-Time Password) and is built to integrate seamlessly with various authentication systems.

## How to Install OTP-Manager

### Prerequisites

- Python 3.6 or higher
- Flask

### Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/Migrim/OTP-Manager.git
    ```
2. Navigate to the project directory:
    ```bash
    cd OTP-Manager
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Run the application:
    ```bash
    python app.py
    ```

## How to Configure OTP-Manager

1. Open the configuration file `config.ini` located in the project directory.
2. Update the following settings:

    ```ini
    [server]
    port = 5002
    secret_key = your-secret-key

    [database]
    path = instance/otp.db
    ```

3. Save the changes and restart the application.

## How to Use OTP-Manager

1. Open your web browser and navigate to `http://localhost:5002` (or the port you set in the config).
2. Log in with the pre-configured admin credentials:
    - Username: `admin`
    - Password: `1234`
3. Change the admin password and create a new user for yourself. Note that new users can only be created by the "admin" user.
4. To add a new OTP entry:
    - Click on "Add".
    - Enter the service name (must be at least 4 letters), the secret key, and optionally an email.
    - Choose a company. If no company exists, you need to create one first under `Management > Company Settings`.
    - Click "Save".
5. To view the OTP for a service, navigate to the service entry and the OTP will be displayed.
