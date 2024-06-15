# Flask Todo App

This is a Flask application for managing todo items with user authentication using Keycloak and payment integration using Stripe.

## Prerequisites

- Python 3.10.0
- Keycloak
- Stripe account

## Installation

1. **Clone the repository**:

    ```bash
    https://github.com/Yash-Bari/todo-app-keycloak.git
    cd todo-app-keycloak
    ```

2. **activate a virtual environment**:

    ```bash
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4. **Create a `.env` file** in the project root and add the following environment variables:

    ```plaintext
    FLASK_SECRET_KEY=your_secret_key
    SQLALCHEMY_DATABASE_URI=sqlite:///todos.db
    STRIPE_SECRET_KEY=your_stripe_secret_key
    STRIPE_PUBLIC_KEY=your_stripe_public_key
    KEYCLOAK_SERVER_URL=http://localhost:8080/auth
    KEYCLOAK_REALM=todo-flask
    KEYCLOAK_CLIENT_ID=todo-flask
    KEYCLOAK_CLIENT_SECRET=your_keycloak_client_secret
    ```

## Keycloak Setup

### Installation

1. **Download Keycloak** from the [official website](https://www.keycloak.org/downloads). Choose the ZIP distribution.

2. **Extract the Keycloak ZIP file** to your desired directory.

3. **Navigate to the Keycloak bin directory**:

    ```bash
    cd path/to/keycloak/bin
    ```

4. **Start Keycloak**:

    ```bash
   kc.bat start-dev
    ```

5. **Create an admin user**:
    Open a browser and visit localhost at 8080 port:

    ```bash
    http://localhost:8080/
    ```

### Realm Creation

1. **Log in to the Keycloak admin console** at `http://localhost:8180/auth` with the credentials (`admin/admin`).

2. **Create a new realm**:
    - Click on `Add realm`.
    - Enter `todo-flask` as the name.
    - Click on `Create`.

### Client Creation

1. **Create a new client**:
    - In the `todo-flask` realm, go to `Clients`.
    - Click on `Create`.
    - Enter `todo-flask` as the `Client ID`.
    - Select `openid-connect` as the `Client Protocol`.
    - Click on `Save`.

2. **Configure the client**:
   -Root URL 'http://127.0.0.1:5000'
   -Home URL 'http://127.0.0.1:5000'
   -Valid redirect URIs 'http://127.0.0.1:5000/auth/callback' 'http://localhost:5000/auth/callback'
   -Valid post logout redirect URIs 'http://127.0.0.1:5000/'
    - Click on `Save`.

3. **Obtain the client secret**:
    - In the `Credentials` tab, copy the `Secret`.

4. **Update the `.env` file** with the client secret:

    ```plaintext
    KEYCLOAK_CLIENT_SECRET=your_obtained_client_secret
    ```

### User Creation

1. **Create a new user**:
    - In the `todo-flask` realm, go to `Users`.
    - Click on `Add user`.
    - Enter the username.
    - Click on `Save`.

2. **Set the user password**:
    - Go to the `Credentials` tab.
    - Set a password.
    - Turn off `Temporary` to prevent the user from needing to reset their password on first login.
    - Click on `Set Password`.

## Running the Application

1. **Start the Flask application**:

    ```bash
    python app.py
    ```

2. **Open the application** in your browser at `http://localhost:5000`.

## Usage

- **Log in** with the user credentials created in Keycloak.
- **Manage todos** (add, edit, delete).
- **Upgrade to Pro** via Stripe for additional features.
- **Access the graphql interface**
   ```bash
    http://127.0.0.1:5000/graphql
    ```
