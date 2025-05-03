# Silcas Bot Commands Guide

This document provides information about all available commands in the Silcas Bot and how to use them.

## Basic Commands

### Help Command

The help command shows a list of all available commands and their descriptions.

- **Usage**: `/help`
- **Description**: Shows all available commands with descriptions
- **Permissions**: Everyone can use this command

### Ping Command

The ping command tests if the bot is working and shows the current latency.

- **Usage**: `/ping`
- **Description**: Tests if the bot is working and shows the latency
- **Permissions**: Everyone can use this command

## Moderation Commands

### Ban Command

The ban command allows moderators to ban users from the server.

- **Usage**: `/ban @user [reason]`
- **Description**: Bans a user from the server
- **Parameters**:
  - `@user`: The user to ban (mention or ID)
  - `reason`: The reason for the ban (optional)
- **Permissions**: Requires the "Ban Members" permission

### Unban Command

The unban command allows moderators to remove a ban from a user.

- **Usage**: `/unban [user_id] [reason]`
- **Description**: Removes a ban from a user
- **Parameters**:
  - `user_id`: The ID of the user to unban
  - `reason`: The reason for the unban (optional)
- **Permissions**: Requires the "Ban Members" permission

### Mute Command

The mute command allows moderators to temporarily mute users in the server.

- **Usage**: `/mute @user [duration] [reason]`
- **Description**: Temporarily mutes a user in the server
- **Parameters**:
  - `@user`: The user to mute (mention or ID)
  - `duration`: The duration of the mute in minutes (default: 10)
  - `reason`: The reason for the mute (optional)
- **Permissions**: Requires the "Moderate Members" permission

### Timeout Command

The timeout command is an alias for the mute command, providing the same functionality with a different name.

- **Usage**: `/timeout @user [duration] [reason]`
- **Description**: Temporarily gives a user a timeout in the server
- **Parameters**:
  - `@user`: The user to timeout (mention or ID)
  - `duration`: The duration of the timeout in minutes (default: 10)
  - `reason`: The reason for the timeout (optional)
- **Permissions**: Requires the "Moderate Members" permission

### Unmute Command

The unmute command allows moderators to remove a mute from a user.

- **Usage**: `/unmute @user`
- **Description**: Removes a mute from a user
- **Parameters**:
  - `@user`: The user to unmute (mention or ID)
- **Permissions**: Requires the "Moderate Members" permission

### Untimeout Command

The untimeout command is an alias for the unmute command, providing the same functionality with a different name.

- **Usage**: `/untimeout @user`
- **Description**: Removes a timeout from a user
- **Parameters**:
  - `@user`: The user to remove the timeout from (mention or ID)
- **Permissions**: Requires the "Moderate Members" permission

## Security Commands

### Scan Link Command

The scan link command allows users to scan URLs for potential threats.

- **Usage**: `/scanlink [url]`
- **Description**: Scans a URL for potential threats
- **Parameters**:
  - `url`: The URL to scan
- **Permissions**: Everyone can use this command

### Scan Media Command

The scan media command allows users to scan images and videos for inappropriate content.

- **Usage**: `/scanmedia [attachment]`
- **Description**: Scans an image or video for inappropriate content
- **Parameters**:
  - `attachment`: The image or video to scan (upload when using the command)
- **Permissions**: Everyone can use this command

## Administrative Commands

### Sync Command

The sync command synchronizes slash commands with Discord to make them visible.

- **Usage**: `/sync [guild_only]`
- **Description**: Synchronizes slash commands with Discord
- **Parameters**:
  - `guild_only`: Whether to sync only to the current server (default: true)
- **Permissions**: Everyone can use this command, but it's primarily for administrators

### Refresh Command

The refresh command refreshes the bot to apply code changes without restarting.

- **Usage**: `/refresh`
- **Description**: Refreshes the bot to apply code changes
- **Permissions**: Only administrators can use this command

## Troubleshooting

If slash commands aren't visible in Discord:

1. Use `/sync` to manually synchronize commands
2. Make sure the bot has the correct scopes (bot AND applications.commands)
3. It can take up to an hour for global commands to appear in all servers
4. If you're still having issues, try reinviting the bot with the correct scopes

If you encounter permission errors:

1. Make sure the bot has the necessary permissions in your server
2. Ensure the bot's role is positioned higher in the role hierarchy than the users it needs to moderate
3. Check that you have the required permissions to use the command