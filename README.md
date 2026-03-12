  Project Structure                                                                                                           
                                                                                                                              
  Dovecot_WebInterface/                                                                                                       
  ├── app/                                                                                                                    
  │   ├── main.py              # FastAPI entry point                                                                          
  │   ├── config.py            # Environment configuration                                                                    
  │   ├── database.py          # SQLite models (admin_users, sessions, alerts)                                                
  │   ├── api/                                                                                                                
  │   │   ├── auth.py          # Login/logout endpoints                                                                       
  │   │   ├── users.py         # User management API                                                                          
  │   │   ├── queue.py         # Mail queue API                                                                               
  │   │   ├── logs.py          # Log viewing API                                                                              
  │   │   ├── storage.py       # Storage monitoring API                                                                       
  │   │   └── partials.py      # HTMX partial templates                                                                       
  │   ├── core/                                                                                                               
  │   │   ├── security.py      # Password hashing, sessions, auth                                                             
  │   │   └── permissions.py   # IPC client for privileged helper                                                             
  │   └── templates/           # Jinja2 + HTMX templates                                                                      
  ├── privileged/                                                                                                             
  │   └── server.py            # Root-level helper daemon                                                                     
  ├── systemd/                 # Service files                                                                                
  ├── manage.py                # CLI admin tool                                                                               
  ├── setup.sh                 # Installation script                                                                          
  ├── requirements.txt                                                                                                        
  └── .env.example                                                                                                            
                                                                                                                              
  Key Features                                                                                                                
                                                                                                                              
  1. User Management - Create/delete system users, set passwords, manage Dovecot quotas                                       
  2. Mail Queue - View, flush, delete, hold/release messages with auto-refresh                                                
  3. Log Viewer - Real-time log streaming via WebSocket, filtering by level/service                                           
  4. Storage Monitoring - Disk usage, per-user mailbox sizes, historical tracking                                             
  5. Alerts - Configurable rules for storage/queue thresholds with email/webhook notifications                                
                                                                                                                              
  Security Model                                                                                                              
                                                                                                                              
  - Privilege separation: Web app runs as www-data, communicates with root-level helper via Unix socket                       
  - Command allowlisting: Helper only accepts predefined operations with strict input validation                              
  - Session-based auth: Bcrypt passwords, secure cookies, rate limiting on login                                              
                                                                                                                              
  To Get Started                                                                                                              
                                                                                                                              
  1. Install dependencies:                                                                                                    
  python3 -m venv venv                                                                                                        
  source venv/bin/activate                                                                                                    
  pip install -r requirements.txt                                                                                             
  2. Initialize database and create admin:                                                                                    
  python manage.py init-db                                                                                                    
  python manage.py create-admin                                                                                               
  3. Run locally for development:                                                                                             
  uvicorn app.main:app --reload                                                                                               
  4. For production (on your mail server):                                                                                    
  sudo ./setup.sh                                                                                                             
                                                                                                                              
  The console will be available at http://localhost:8000. For production, configure nginx as a reverse proxy with HTTPS.  