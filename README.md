# Project: PKI and Shared Password Manager (BSEP)

## Project Overview

This project implements a **Public Key Infrastructure (PKI)** system and a **Shared Password Manager** as a requirement for the "Security in Electronic Business Systems" (BSEP) course. The **backend** is developed using **Java Spring Boot** and associated frameworks, while the **frontend** is a separate application developed in **Angular**. [BSEP Angular Frontend](https://github.com/akoskissak/pki-system-frontend)

The PKI is designed to manage digital certificates, ensuring secure user and device authentication, as well as communication protection. The Shared Password Manager offers secure storage and sharing of confidential data (like passwords and access credentials) using the user's existing public/private key pair from the PKI system.

---

## Key Features

### Public Key Infrastructure (PKI)

* **Certificate Management:** Supports issuing, viewing, downloading, and revoking certificates
* **Certificate Types:** Supports issuing **Root** (self-signed), **Intermediate**, and **End-Entity (EE)** certificates.
* **CSR Support:** End-Entity users can upload a **Certificate Signing Request (CSR)** to request an EE certificate.
* **Revocation:** Any user can revoke a certificate, specifying a reason according to the X.509 standard.
* **Templates:** CA users can create and use templates to predefine certificate extensions (e.g., Key Usage, Extended Key Usage) and subject properties (Common Name, Subject Alternative Names) using regular expressions for validation.
* **Secure Storage:** Private keys for CA certificates are stored in a keystore protected by a randomly generated, **encrypted password**.

### Shared Password Manager

* **EE User Only:** The functionality is exclusively available to End-Entity users who possess their own public/private key pair.
* **Encryption at Frontend:** Passwords are encrypted on the frontend using the user's **public key** before being stored in the database.
* **Private Key Security:** The user's private key is **never stored on the server**. Decryption is performed locally on the frontend using the **WEB Crypto API** and the private key provided by the user.
* **Password Sharing:** Passwords can be securely shared with other EE users by re-encrypting the password with the recipient's public key.

### Security and Authentication

* **User Registration:** Ordinary users register by providing an email, password, name, surname, and organization, followed by identity confirmation via a time-limited, single-use email activation link.
* **Login Security:** Login requires an email and password, plus solving a **reCAPTCHA**.
* **HTTPS Communication:** All client-server communication is secured using the **HTTPS** protocol.
* **Active Token Tracking:** Users can view a list of active **JWT tokens** (sessions) in their profile and individually revoke any token to log out from a specific device.
* **Audit Logging:** Implemented a robust **logging mechanism** for all security-significant events to ensure non-repudiation, with a focus on log rotation.
* *Attack Protection:** The system is resistant to **SQL Injection** (using prepared statements/framework handling) and **XSS** (Cross-Site Scripting) via input validation, sanitization, and output escaping.

---

## Technology Stack

| Technology | Role |
| :--- | :--- |
| **Java** | Core backend language. |
| **Spring Boot** | Main backend framework. |
| **Angular** | Main frontend framework. |
| **PostgreSQL** | Persistent data storage. |
| **Bouncy Castle** | Third-party cryptography provider for advanced PKI features. |
| **WEB Crypto API** | Used on the Angular frontend for local decryption of passwords. |
| **Maven** | Build automation and dependency management for the backend. |
| **npm** | Dependency management for the Angular frontend. |

---

## Prerequisites

To run this project locally, you need to have the following installed:

* **Java Development Kit (JDK) 8 or higher** (JDK 17 recommended).
* **Maven 3.x** or **Gradle** (for the backend).
* **Node.js** and **npm** or **Yarn** (for the frontend).
* **Angular CLI** (globally installed).
* **PostgreSQL**
* **Git**.

---

## Getting Started

The project is split into two repositories: one for the backend (this repo) and one for the Angular frontend.

### 1. Backend Setup and Run

1.  **Clone the Repository:**
    ```bash
    git clone <BACKEND_REPOSITORY_URL>
    cd <backend_project_name>
    ```

2.  **Database Configuration:**
    * Create a new database named `\[DATABASE NAME]`.
    * Update the backend configuration file (`src/main/resources/application.properties` or `application.yml`) with your database credentials.

3.  **Run the Backend:**
    ```bash
    # Build the project
    mvn clean install

    # Run the application
    mvn spring-boot:run
    ```
    *The backend server will typically start on `https://localhost:8443`.*

### 2. Frontend Setup and Run

1.  **Clone the Frontend Repository:**
    ```bash
    git clone <FRONTEND_REPOSITORY_URL>
    cd <frontend_project_name>
    ```

2.  **Install Dependencies:**
    ```bash
    npm install
    ```

3.  **Run the Frontend:**
    ```bash
    ng serve
    ```
    *The Angular application will typically be accessible in your browser at `https://localhost:4200`.*

---

## Advanced and Additional Features
* **2FA (Two-Factor Authentication):** Implementation of 2FA using a mobile authenticator application.
