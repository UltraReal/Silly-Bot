# Changes Made to Fix Slash Commands

## Summary of Changes

1. **Added Slash Command Versions**:
   - Added slash command version of `/scanlink` to scan URLs for potential threats
   - Added slash command version of `/scanmedia` to scan images and videos for inappropriate content
   - Added moderation commands: `/ban`, `/unban`, `/mute`, `/unmute`, `/timeout`, `/untimeout`
   - Added utility commands: `/help`, `/refresh`, `/sync`
   - Kept the original prefix commands for backward compatibility

2. **Updated Help Command**:
   - Added the new commands to the help menu so users can see all available commands
   - Improved command descriptions

3. **Automatic Command Registration**:
   - Modified the `on_ready` event to automatically sync slash commands with Discord at startup
   - This ensures commands are always registered and visible

4. **Fixed Encoding Issues**:
   - Updated run_bot.bat to use UTF-8 encoding to prevent character encoding errors

## How to Use the New Commands

1. **URL Scanning**:
   - Use `/scanlink [url]` to scan a URL for potential threats
   - The bot will analyze the URL and report if it's safe or potentially dangerous

2. **Media Scanning**:
   - Use `/scanmedia [attachment]` to scan an image or video for inappropriate content
   - Upload or select a file when using the command

3. **User Moderation**:
   - Use `/ban @user [reason]` to ban a user from the server
   - Use `/unban [user_id] [reason]` to remove a ban from a user
   - Use `/mute @user [duration] [reason]` to temporarily mute a user
   - Use `/timeout @user [duration] [reason]` to temporarily timeout a user (alias for mute)
   - Use `/unmute @user` to remove a mute from a user
   - Use `/untimeout @user` to remove a timeout from a user (alias for unmute)
   - Duration for mute/timeout is in minutes (default: 10 minutes)
   - Ban/unban commands require the 'Ban Members' permission
   - Mute/unmute/timeout/untimeout commands require the 'Moderate Members' permission

4. **Syncing Commands**:
   - If commands aren't visible, use `/sync` to manually synchronize them with Discord
   - Note that it can take up to an hour for global commands to appear in all servers

## Required Bot Permissions

The bot requires the following permissions to function properly:
- Moderate Members: For applying timeouts
- Ban Members: For banning users
- Manage Messages: For deleting messages
- Send Messages: For sending messages
- Embed Links: For sending embeds
- Read Message History: For reading messages

## Troubleshooting

If you encounter the "[ERROR] User lacks required permissions: ['ban_members']" message:
1. Make sure the bot has the 'Ban Members' permission in your Discord server
2. Check that the bot's role is positioned higher in the role hierarchy than the users it needs to moderate
3. Ensure you're using an account with the proper permissions if you're trying to use the ban command