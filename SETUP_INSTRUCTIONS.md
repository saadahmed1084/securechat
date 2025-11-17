# Secure Chat Application - Setup Instructions (MySQL)

## Prerequisites
- Python 3.8 or higher
- MySQL 8.0 or higher installed locally
- Git (optional, if cloning repository)

---

## Step 1: Install MySQL

### Windows:
1. Download MySQL Installer from: https://dev.mysql.com/downloads/installer/
2. Run the installer and select "Developer Default" or "Server only"
3. During installation:
   - Set root password (remember this!)
   - Keep default port: 3306
   - Start MySQL Server as a Windows Service
4. Verify installation: Open Command Prompt and run:
   ```cmd
   mysql --version
   ```

### Linux (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
sudo mysql_secure_installation
```

### macOS:
```bash
# Using Homebrew
brew install mysql
brew services start mysql
```

---

## Step 2: Create Database and User

Open MySQL command line or MySQL Workbench:

### Option A: MySQL Command Line
```bash
# Windows: Open Command Prompt or MySQL Command Line Client
# Linux/Mac: Open terminal
mysql -u root -p
# Enter your root password when prompted
```

### Option B: MySQL Workbench
- Open MySQL Workbench
- Connect to your local MySQL instance

### Then run these SQL commands:

```sql
-- Create database
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';

-- Grant privileges
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify (optional)
SHOW DATABASES;
SELECT user, host FROM mysql.user WHERE user = 'scuser';
```

Exit MySQL:
```sql
EXIT;
```

---

## Step 3: Python Environment Setup

Open terminal/command prompt in the project directory:

```bash
# Navigate to project directory
cd securechat-skeleton-main

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

---

## Step 4: Configure Database Connection (Optional)

The application uses default MySQL settings. If your MySQL setup differs, create a `.env` file:

```bash
# Create .env file in project root
# Windows:
type nul > .env
# Linux/Mac:
touch .env
```

Edit `.env` file with your MySQL settings:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=scuser
DB_PASSWORD=scpass
DB_NAME=securechat
SERVER_HOST=localhost
SERVER_PORT=8888
```

**Note:** If you don't create `.env`, the application will use these defaults automatically.

---

## Step 5: Initialize Database Schema

```bash
# Make sure virtual environment is activated
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Initialize database tables
python -m app.storage.db --init
```

Expected output:
```
✓ Database initialized successfully
```

**Troubleshooting:**
- If you get "Access denied", check your MySQL user credentials
- If you get "Can't connect to MySQL server", ensure MySQL service is running:
  - Windows: Check Services (services.msc) for "MySQL80"
  - Linux: `sudo systemctl status mysql`
  - Mac: `brew services list`

---

## Step 6: Generate Certificates

```bash
# Generate Root CA certificate
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

This creates the following files in `certs/` directory:
- `ca_cert.pem` - Root CA certificate
- `ca_key.pem` - Root CA private key (keep secret!)
- `server_cert.pem` - Server certificate
- `server_key.pem` - Server private key (keep secret!)
- `client_cert.pem` - Client certificate
- `client_key.pem` - Client private key (keep secret!)

---

## Step 7: Run the Server

Open a **new terminal window** (keep it open):

```bash
# Navigate to project directory
cd securechat-skeleton-main

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Run server
python -m app.server
```

Expected output:
```
✓ Database initialized successfully
✓ Server listening on localhost:8888
  Waiting for client connections...
```

**Keep this terminal open!** The server must be running for clients to connect.

---

## Step 8: Register a User (First Time)

Open a **second terminal window**:

```bash
# Navigate to project directory
cd securechat-skeleton-main

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Register a new user
python -m app.client --action register --email user@example.com --username alice --password mypassword123
```

Expected output:
```
✓ Connected to server localhost:8888
✓ Server certificate validated: server.local
✓ AES key derived from DH exchange
✓ Registration successful
```

---

## Step 9: Login and Start Chatting

In the same terminal (or a new one):

```bash
# Make sure virtual environment is activated
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Login
python -m app.client --action login --username alice --password mypassword123
```

After successful login, you'll see:
```
✓ Session established. Ready for chat messages.

✓ Entering chat mode. Type messages and press Enter to send.
  Type 'quit' or 'exit' to disconnect.
```

**Now you can type messages!** Example:
```
Hello, this is a secure message!
How are you?
This message is encrypted!
```

Each message will show:
```
✓ Message [1] sent
✓ Message [2] sent
```

**To disconnect**, type `quit` or `exit` and press Enter.

---

## Step 10: Session Closure and Receipts

When you disconnect (type `quit` or `exit`):

1. Client generates a receipt
2. Client sends receipt to server
3. Server verifies client receipt
4. Server generates and sends its receipt
5. Both receipts are saved to `transcripts/` directory

You'll see output like:
```
✓ Client receipt sent: seq 1-3
  Transcript hash: a1b2c3d4...
✓ Client receipt saved to: transcripts/server_1234567890_client.local_client_receipt.json
✓ Server receipt verified: seq 1-3
✓ Server receipt saved to: transcripts/server_1234567890_client.local_server_receipt.json
```

---

## Step 11: Verify Receipts Offline

After a session, verify receipts for non-repudiation:

```bash
# Make sure virtual environment is activated
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Verify client receipt
python scripts/verify_receipt.py --receipt transcripts/server_<timestamp>_<client_cn>_client_receipt.json --transcript transcripts/server_<timestamp>_<client_cn>.txt --cert certs/client_cert.pem

# Verify server receipt
python scripts/verify_receipt.py --receipt transcripts/server_<timestamp>_<client_cn>_server_receipt.json --transcript transcripts/server_<timestamp>_<client_cn>.txt --cert certs/server_cert.pem
```

Replace `<timestamp>` and `<client_cn>` with actual values from your transcript files.

Expected output:
```
✓ Receipt verification successful
  The receipt is valid and the transcript has not been modified.
  This provides non-repudiation evidence.
```

---

## Complete Command Reference

### Server:
```bash
python -m app.server
```

### Client - Register:
```bash
python -m app.client --action register --email <email> --username <username> --password <password>
```

### Client - Login:
```bash
python -m app.client --action login --username <username> --password <password>
```

### Client - Custom Host/Port:
```bash
python -m app.client --host localhost --port 8888 --action login --username <username> --password <password>
```

### Database Initialization:
```bash
python -m app.storage.db --init
```

### Verify Receipt:
```bash
python scripts/verify_receipt.py --receipt <receipt_file> --transcript <transcript_file> --cert <certificate_file>
```

---

## Troubleshooting

### MySQL Connection Issues

**Error: "Can't connect to MySQL server"**
- Ensure MySQL service is running:
  - Windows: Open Services (`services.msc`), find "MySQL80", ensure it's "Running"
  - Linux: `sudo systemctl start mysql`
  - Mac: `brew services start mysql`

**Error: "Access denied for user 'scuser'@'localhost'"**
- Verify user exists: `SELECT user, host FROM mysql.user WHERE user = 'scuser';`
- Recreate user if needed:
  ```sql
  DROP USER IF EXISTS 'scuser'@'localhost';
  CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
  GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
  FLUSH PRIVILEGES;
  ```

**Error: "Unknown database 'securechat'"**
- Create database: `CREATE DATABASE securechat;`
- Then run: `python -m app.storage.db --init`

### Certificate Issues

**Error: "Server certificate not found"**
- Run certificate generation (Step 6)
- Ensure `certs/` directory exists and contains all certificate files

**Error: "BAD_CERT: Certificate validation failed"**
- Ensure all certificates are generated from the same CA
- Regenerate certificates if needed

### Port Issues

**Error: "Address already in use" or "Port already in use"**
- Change server port:
  - Windows: `set SERVER_PORT=8889` then run server
  - Linux/Mac: `export SERVER_PORT=8889` then run server
- Or find and kill the process using port 8888:
  - Windows: `netstat -ano | findstr :8888`
  - Linux/Mac: `lsof -i :8888`

### Other Issues

**"Module not found" errors**
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`

**"REPLAY" or "SIG_FAIL" errors**
- These indicate message integrity issues
- Restart the session (disconnect and reconnect)

---

## File Structure After Setup

```
securechat-skeleton-main/
├── certs/
│   ├── ca_cert.pem          # Root CA certificate
│   ├── ca_key.pem           # Root CA private key (SECRET!)
│   ├── server_cert.pem       # Server certificate
│   ├── server_key.pem        # Server private key (SECRET!)
│   ├── client_cert.pem       # Client certificate
│   └── client_key.pem        # Client private key (SECRET!)
├── transcripts/
│   ├── server_<timestamp>_<client>.txt
│   ├── server_<timestamp>_<client>_client_receipt.json
│   └── server_<timestamp>_<client>_server_receipt.json
├── .env                     # Optional: Database configuration
├── app/                     # Application code
└── scripts/                 # Utility scripts
```

---

## Quick Start Checklist

- [ ] MySQL installed and running
- [ ] Database `securechat` created
- [ ] User `scuser` created with password `scpass`
- [ ] Python virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Database initialized (`python -m app.storage.db --init`)
- [ ] Certificates generated (CA, server, client)
- [ ] Server running (`python -m app.server`)
- [ ] User registered
- [ ] Ready to chat!

---

## Example Session Flow

1. **Terminal 1** (Server):
   ```bash
   python -m app.server
   ```

2. **Terminal 2** (Client - Register):
   ```bash
   python -m app.client --action register --email test@test.com --username alice --password pass123
   ```

3. **Terminal 2** (Client - Login & Chat):
   ```bash
   python -m app.client --action login --username alice --password pass123
   # Then type messages and press Enter
   # Type 'quit' to disconnect
   ```

4. **Verify Receipts**:
   ```bash
   python scripts/verify_receipt.py --receipt transcripts/..._client_receipt.json --transcript transcripts/....txt --cert certs/client_cert.pem
   ```

---

## Security Notes

- **Never commit** certificate files (`.pem` files in `certs/`)
- **Never commit** private keys (`*_key.pem` files)
- **Never commit** `.env` file with passwords
- **Never commit** transcript files (they may contain sensitive data)
- All these are already in `.gitignore` for safety

---

That's it! Your secure chat application is ready to use with MySQL! 🎉

