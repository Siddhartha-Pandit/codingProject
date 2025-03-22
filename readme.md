## Setting up environment

### 1. Update the credentials in the .env file which is in root directory where manage.py is present.
- make an account in the twillio.py and get the credentials such as twilio accunt id (TWILIO_ACCOUNT_SID), twilio auth token(TWILIO_AUTH_TOKEN) , twilio phone number and update (TWILIO_PHONE_NUMBER) accordingly in the .env file. Twilio is require to verify the phone number after registering

- Then get the credentials from the email provider such as host (EMAIL_HOST), port (EMAIL_PORT), host user email (EMAIL_HOST_USER), email host password (EMAIL_HOST_PASSWORD) and default from email (DEFAULT_FROM_EMAIL). These you can get from the any email provider in this application i have used the gmail 

- update the setting below in <b>.env</b> file
```
# Redis settings
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# Twilio settings
TWILIO_ACCOUNT_SID=your_twilio_account_sid_here
TWILIO_AUTH_TOKEN=your_twilio_auth_token_here
TWILIO_PHONE_NUMBER=your_twilio_phone_number_here

# Email settings
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com  # Change if using a different SMTP provider
EMAIL_PORT=587
EMAIL_HOST_USER=your_email@example.com    # e.g., myemail@gmail.com
EMAIL_HOST_PASSWORD=your_email_password     # e.g., emailpassword
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False 
DEFAULT_FROM_EMAIL=your_email@example.com   # Should match EMAIL_HOST_USER


# PostgreSQL settings for Docker container
POSTGRES_DB=spamgaurd_db
POSTGRES_USER=spamgaurd_user
POSTGRES_PASSWORD=supersecretpassword
POSTGRES_HOST=postgres
POSTGRES_PORT=5432


```

### 2. Then open terminal and navigate to root folder where manage.py is present the write the code 

```
docker-compose up --build
```

> **Warning:**  
> **Make sure that `docker` is installed**  
> Make sure your cresidential in `.env` file is properly configured.  
> Always update the credentials in the `.env` file with your own secure values before deployment.


#### finally after some time docker instance is created and you can test the apis
