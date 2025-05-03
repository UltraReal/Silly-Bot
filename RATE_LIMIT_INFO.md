# Discord Rate Limit Information

## What Are Rate Limits?

Discord imposes rate limits on API requests to prevent abuse. When you register slash commands, especially global commands that apply to all servers, Discord limits how many requests you can make in a short period.

## Rate Limit Error Message

If you see this error message:
```
[WARNING] discord.http: We are being rate limited. PUT https://discord.com/api/v10/applications/YOUR_BOT_ID/commands responded with 429. Retrying in XX seconds.
```

This means:
1. Your bot received a 429 error (Too Many Requests)
2. Discord is asking you to wait for the specified time before trying again
3. The library will automatically retry after this time

## How to Avoid Rate Limits

### 1. Use Guild-Specific Commands During Development

The bot now has options to sync commands only to specific guilds instead of globally:

- When using the `/sync` command, the default is now `guild_only=True`
- This will only register commands to the current server, avoiding global rate limits
- Only use global syncing when you're ready to deploy to all servers

### 2. Reduce Command Registration Frequency

- Avoid restarting the bot frequently during development
- Each restart triggers a new sync of commands
- The bot now only syncs to the first guild at startup to avoid rate limits

### 3. Wait Between Sync Attempts

- If you hit a rate limit, wait at least 5-10 minutes before trying again
- Discord's rate limits reset after a period of time

## Command Sync Options

### Using the `/sync` Command

The `/sync` command now has a `guild_only` parameter:

- `/sync guild_only:True` - Syncs commands only to the current server (default)
- `/sync guild_only:False` - Syncs commands globally to all servers

### Automatic Sync at Startup

- The bot now only syncs commands to the first guild at startup
- This prevents rate limits when restarting the bot
- To sync globally, use the `/sync guild_only:False` command manually

## When to Use Global Sync

Only use global sync (`guild_only:False`) when:

1. You've made final changes to your commands
2. You're ready to deploy to all servers
3. You haven't hit any rate limits recently

Remember that global commands can take up to an hour to appear in all servers, while guild-specific commands appear immediately.