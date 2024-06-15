# Flask Todo Application

This is a Flask-based Todo application with OAuth2 authentication using Keycloak, GraphQL API support, and Stripe integration for Pro user subscriptions.

## Table of Contents

1. [Setup Instructions](#setup-instructions)
2. [Keycloak Setup](#keycloak-setup)
   - [Installation](#installation)
   - [Realm Creation](#realm-creation)
   - [Client Creation](#client-creation)
   - [User Creation](#user-creation)
3. [Environment Variables](#environment-variables)
4. [Running the Application](#running-the-application)

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- Node.js (for managing Keycloak)
- Docker (for running Keycloak)

### Installing Dependencies

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/flask-todo-app.git
    cd flask-todo-app
    ```

2. Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Keycloak Setup

### Installation

1. Pull the Keycloak Docker image:

    ```bash
    docker pull quay.io/keycloak/keycloak:latest
    ```

2. Run the Keycloak container:

    ```bash
    docker run -d -p 8080:8080 --name keycloak \
    -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev
    ```

3. Access the Keycloak admin console at `http://localhost:8080` and log in with the admin credentials (`admin/admin`).

### Realm Creation

1. In the Keycloak admin console, click on "Add realm" in the top left dropdown menu.
2. Name your realm `todo-flask` and click "Create".

### Client Creation

1. In the Keycloak admin console, select the `todo-flask` realm.
2. Go to the "Clients" section and click "Create".
3. Fill out the form as follows:
   - Client ID: `todo-flask`
   - Client Protocol: `openid-connect`
4. Click "Save".
5. Configure the client settings:
   - Access Type: `confidential`
   - Valid Redirect URIs: `http://localhost:5000/auth/callback`
   - Web Origins: `http://localhost:5000`
6. Click "Save".
7. Go to the "Credentials" tab and copy the Secret value. Replace the placeholder in your `.env` file with this secret.

### User Creation

1. In the Keycloak admin console, go to the "Users" section and click "Add user".
2. Fill out the form with the user details and click "Save".
3. Go to the "Credentials" tab for the new user, set a password, and ensure "Temporary" is off.

## Environment Variables

Create a `.env` file in the project root and add the following environment variables:

```ini
FLASK_SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///todos.db
KEYCLOAK_CLIENT_ID=todo-flask
KEYCLOAK_CLIENT_SECRET=your_client_secret
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=todo-flask
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PUBLIC_KEY=your_stripe_public_key
UPLOAD_FOLDER=static/uploads
