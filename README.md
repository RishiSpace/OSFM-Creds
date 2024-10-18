# OSFM Credentials Manager

## Overview

OSFM-Creds is a secure credential storage system designed to store sensitive information such as passwords, API keys, and other credentials. The system uses end-to-end encryption to ensure that only authorized users can access the stored credentials.

**Features**

*   Secure credential storage with end-to-end encryption
*   Master password protection for added security
*   Store and retrieve credentials for various services and applications
*   Retrieve all credential names for easy access
*   Ctrl+C and exit handling for smooth termination

**Installation**

To install OSFM-Creds, simply clone the repository and run the script. The script will guide you through the setup process.

**Usage**

1.  Run the script and enter the master password to access the credential storage system.
2.  Choose from the following options:
    *   **Store credential**: Store a new credential with a name and value.
    *   **Retrieve credential**: Retrieve a stored credential by name.
    *   **Retrieve all credential names**: Retrieve a list of all stored credential names.
    *   **Exit**: Exit the credential storage system.
3.  Follow the prompts to complete the chosen action.

**Security**

*   The master password is hashed and stored securely in the database.
*   All stored credentials are encrypted with a key derived from the master password.
*   The encryption key is not stored anywhere, ensuring that only authorized users can access the stored credentials.

**Technical Requirements**

*   Python 3.x
*   cryptography library
*   sqlite3 library
*   getpass library
*   os library
*   signal library
*   atexit library

**License**

OSFM-Creds is released under the GPL V3 License.

**Contributing**

Contributions are welcome! Please submit a pull request with your changes and a brief description of the changes.

**Disclaimer**

OSFM-Creds is a secure credential storage system, but it is not foolproof. It is the user's responsibility to ensure the security of their credentials and master password.