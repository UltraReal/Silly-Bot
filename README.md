# Stack Buffer Overflow Detection Bot

This Discord bot monitors messages for patterns that might indicate stack buffer overflow attempts and takes action when detected.

## Setup Instructions

### Step 1: Install Python
For best compatibility, install Python 3.11 from: https://www.python.org/downloads/release/python-3118/

During installation:
- Check "Add Python to PATH"
- Choose "Customize installation"
- Make sure "pip" is selected

### Step 2: Install Required Packages
Open a command prompt and run:
```
pip install discord.py python-dotenv requests virustotal-api flask flask-login matplotlib aiohttp
```

### Step 3: Set Up Your Discord Bot
1. Go to https://discord.com/developers/applications
2. Click "New Application" and give it a name
3. Go to the "Bot" tab
4. Click "Add Bot"
5. Under "Privileged Gateway Intents", enable:
   - Presence Intent
   - Server Members Intent
   - Message Content Intent
6. Click "Reset Token" and copy the new token

### Step 4: Configure the Bot
1. Open the `.env` file
2. Replace `your_new_token_here` with your actual Discord bot token
3. Set the `MOD_LOG_CHANNEL_ID` to the ID of the channel where violations should be logged
4. (Optional) Get a free VirusTotal API key from https://www.virustotal.com/gui/join-us
5. Add your VirusTotal API key to the `.env` file as `VIRUSTOTAL_API_KEY`
6. (Optional) Get an NSFW content detection API key from one of these services:
   - SightEngine: https://sightengine.com/ (recommended)
   - Google Cloud Vision API: https://cloud.google.com/vision
   - AWS Rekognition: https://aws.amazon.com/rekognition
   - DeepAI: https://deepai.org/machine-learning-model/nsfw-detector
7. Add your NSFW API key to the `.env` file as `NSFW_API_KEY`
   - For SightEngine, use the format `user_id:api_secret`

### Step 5: Invite the Bot to Your Server
1. Go to the "OAuth2" tab in the Discord Developer Portal
2. Select "bot" under "SCOPES"
3. Select the following permissions:
   - Manage Messages
   - Moderate Members
   - Send Messages
   - Read Message History
4. Copy the generated URL and open it in your browser
5. Select your server and authorize the bot

### Step 6: Run the Bot
Open a command prompt, navigate to the bot directory, and run:
```
python stackbuffer.py
```

## Features
- Detects potential stack buffer overflow patterns in messages
- Scans all URLs posted in the server for malware, viruses, and IP loggers
- Scans all images and videos for NSFW content
- Provides a `!scanlink` command for users to manually check URLs
- Provides a `!scanmedia` command for users to manually check images and videos
- Silently deletes malicious links and inappropriate media without warning messages
- Times out users who post malicious content
- Logs all URL and media scans (both safe and malicious) to a designated channel
- Includes user information and an IP-like identifier in logs
- Logs all violations to a designated channel with detailed information
- Provides a web-based dashboard with statistics and visualizations
- Password-protected access to the dashboard
- Search and filter functionality for logs

## Dashboard
The bot includes a web-based dashboard that provides statistics, visualizations, and access to logs:

### Accessing the Dashboard
1. Start the bot using the instructions above
2. Open a web browser and go to `http://localhost:5000`
3. Log in with the default credentials:
   - Username: `admin`
   - Password: `admin123`
4. **Important**: Change the default password immediately after logging in

### Dashboard Features
- Overview of URL scans, media scans, and violations with statistics
- Interactive charts and visualizations
- Detailed logs of all URL and media scans
- Records of all violations
- Search and filter functionality
- User management and settings
- Media content type analysis

## Troubleshooting
- If you get an "audioop" error, make sure you're using Python 3.11, not 3.12 or 3.13
- If the bot doesn't connect, check that your token is correct
- If the bot connects but doesn't respond to messages, make sure you've enabled the Message Content Intent
- If the dashboard doesn't start, make sure you've installed all the required packages
- If you can't access the dashboard from another computer, you may need to configure your firewall to allow connections on port 5000
- If you see an "Internal Server Error", check the console for error messages
- If the dashboard shows no data, make sure the bot has been running and collecting data
- If you get a "No module named 'flask'" error, run `pip install flask flask-login matplotlib`
- If you get a "No module named 'aiohttp'" error, run `pip install aiohttp`
- If the dashboard doesn't load properly, try clearing your browser cache or using incognito mode
- If media scanning isn't working, check that you've set up the NSFW_API_KEY correctly in the .env file
- For SightEngine API, make sure the key is in the format `user_id:api_secret`