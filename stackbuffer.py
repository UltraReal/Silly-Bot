import datetime
import os
import re
import requests
import random
import hashlib
import threading
from dotenv import load_dotenv
import sys
import dashboard_db as db
import io
import aiohttp
import discord
from discord.ext import commands

# Load environment variables
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
MOD_LOG_CHANNEL_ID = int(os.getenv("MOD_LOG_CHANNEL_ID", "1337907970620784721"))
TIMEOUT_DURATION = 7 * 24 * 60 * 60  # 1 week in seconds
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
NSFW_API_KEY = os.getenv("NSFW_API_KEY", "")  # API key for NSFW content detection

# Patterns that might indicate a buffer overflow
BOF_PATTERNS = [
    "A" * 100,
    "%x", "%p", "%n",
    "\x90\x90\x90\x90",
    "0x41414141",
]

# URL regex pattern - more comprehensive to catch various URL formats
URL_PATTERN = r'(?:https?://|www\.)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.[a-z]{2,}(?:/[^\s]*)?'

# Note: Discord bots cannot access real IP addresses of users.
# We generate a deterministic IP-like identifier based on the user ID for logging purposes.
# This is NOT a real IP address and should not be treated as such.

# Check if TOKEN is properly set
if not TOKEN or TOKEN == "your_new_token_here":
    print("ERROR: You need to set your Discord bot token in the .env file")
    print("1. Go to https://discord.com/developers/applications")
    print("2. Select your application")
    print("3. Go to the 'Bot' tab")
    print("4. Click 'Reset Token' and copy the new token")
    print("5. Open the .env file and replace 'your_new_token_here' with your actual token")
    sys.exit(1)

# Print important information about slash commands, permissions, and intents
print("┌───────────────────────────────────────────────────────────────────────────┐")
print("│                     SILCAS BOT CONFIGURATIE HANDLEIDING                    │")
print("└───────────────────────────────────────────────────────────────────────────┘")

print("\n┌─ 🔑 GEPRIVILEGIEERDE INTENTS ───────────────────────────────────────────┐")
print("│                                                                           │")
print("│  Deze bot vereist de volgende geprivilegieerde intents:                   │")
print("│   • SERVER MEMBERS INTENT                                                 │")
print("│   • MESSAGE CONTENT INTENT                                                │")
print("│                                                                           │")
print("│  Hoe in te schakelen:                                                     │")
print("│   1. Ga naar: https://discord.com/developers/applications                 │")
print("│   2. Selecteer je bot → 'Bot' tab → 'Privileged Gateway Intents'          │")
print("│   3. Schakel beide intents in → 'Save Changes'                            │")
print("└───────────────────────────────────────────────────────────────────────────┘")

print("\n┌─ 🔗 SLASH COMMANDS CONFIGURATIE ─────────────────────────────────────────┐")
print("│                                                                           │")
print("│  Als slash commands niet zichtbaar zijn:                                  │")
print("│   1. Controleer scopes in Discord Developer Portal:                       │")
print("│      • Ga naar 'OAuth2' → 'URL Generator'                                 │")
print("│      • Selecteer BEIDE scopes: 'bot' EN 'applications.commands'           │")
print("│   2. Nodig de bot opnieuw uit met de gegenereerde URL                     │")
print("│   3. Gebruik het /sync commando in Discord                                │")
print("│   4. Wacht tot een uur voor globale commands                              │")
print("└───────────────────────────────────────────────────────────────────────────┘")

print("\n┌─ 🛡️ BENODIGDE BOT PERMISSIES ───────────────────────────────────────────┐")
print("│                                                                           │")
print("│  • Moderate Members: Voor timeouts                                        │")
print("│  • Ban Members: Voor verbannen van gebruikers                             │")
print("│  • Manage Messages: Voor verwijderen van berichten                        │")
print("│  • Send Messages: Voor sturen van berichten                               │")
print("│  • Embed Links: Voor sturen van embeds                                    │")
print("│  • Read Message History: Voor lezen van berichten                         │")
print("│                                                                           │")
print("│  Bij 'Error 403 Forbidden: Missing Permissions':                          │")
print("│   • Controleer of de bot alle bovenstaande permissies heeft               │")
print("│   • Zorg dat de bot rol HOGER staat in de rollenlijst                     │")
print("│   • Bot kan geen actie uitvoeren op gebruikers met hogere rechten         │")
print("└───────────────────────────────────────────────────────────────────────────┘")

try:
    # Set up intents - only enable what we need
    intents = discord.Intents.default()
    intents.messages = True
    intents.message_content = True  # This is a privileged intent
    intents.guilds = True
    intents.members = True  # This is a privileged intent
    
    # Print warning about privileged intents
    print("\n┌─────────────────────────────────────────────────────────────────────┐")
    print("│ ⚠️  WAARSCHUWING: GEPRIVILEGIEERDE INTENTS VEREIST                   │")
    print("├─────────────────────────────────────────────────────────────────────┤")
    print("│ Deze bot vereist geprivilegieerde intents om correct te werken.      │")
    print("│ Zonder deze intents zal de bot niet kunnen starten of zal beperkt    │")
    print("│ functioneren.                                                        │")
    print("│                                                                       │")
    print("│ Schakel deze in via het Discord Developer Portal:                    │")
    print("│  1. Ga naar: https://discord.com/developers/applications             │")
    print("│  2. Selecteer je bot applicatie → 'Bot' tab                          │")
    print("│  3. Scroll naar 'Privileged Gateway Intents'                         │")
    print("│  4. Schakel 'SERVER MEMBERS INTENT' en 'MESSAGE CONTENT INTENT' in   │")
    print("│  5. Klik op 'Save Changes'                                           │")
    print("└─────────────────────────────────────────────────────────────────────┘\n")
    
    # Create bot instance with both prefix commands and slash commands
    bot = commands.Bot(command_prefix="/", intents=intents, help_command=None)
    
    # Helper function to send temporary messages that delete after a delay
    async def send_temp_message(ctx, content, delete_after=10):
        """Send a message that will be automatically deleted after a specified number of seconds"""
        print(f"[TEMP MESSAGE] Sending temporary message to {ctx.author}: '{content}' (deletes after {delete_after}s)")
        return await ctx.send(content, delete_after=delete_after)
    
    # Add a global error handler for application commands (slash commands)
    @bot.tree.error
    async def on_app_command_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
        command_name = interaction.command.name if interaction.command else "unknown"
        print(f"[SLASH ERROR] Error in slash command '{command_name}' from {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
        
        if isinstance(error, discord.app_commands.errors.MissingPermissions):
            print(f"[SLASH ERROR] User lacks required permissions: {error.missing_permissions}")
            await interaction.response.send_message(f"❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Ontbrekende permissies: {', '.join(error.missing_permissions)}", ephemeral=True)
        elif isinstance(error, discord.app_commands.errors.CommandOnCooldown):
            print(f"[SLASH ERROR] Command on cooldown, retry after {error.retry_after:.1f} seconds")
            await interaction.response.send_message(f"⏳ Dit commando heeft een cooldown. Probeer het opnieuw over {error.retry_after:.1f} seconden.", ephemeral=True)
        else:
            # Log the error
            print(f"[SLASH ERROR] Unhandled app command error: {error}")
            
            # Send a generic error message
            try:
                if not interaction.response.is_done():
                    print(f"[SLASH ERROR] Sending error response")
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden bij het uitvoeren van dit commando: {str(error)}", ephemeral=True)
                else:
                    print(f"[SLASH ERROR] Sending error followup")
                    await interaction.followup.send(f"❌ Er is een fout opgetreden bij het uitvoeren van dit commando: {str(error)}", ephemeral=True)
                print(f"[SLASH ERROR] Error message sent to user")
            except Exception as msg_error:
                print(f"[SLASH ERROR] Could not send error message: {msg_error}")
    
    # Create a function to generate the help embed
    def create_help_embed():
        """Create the help embed with all commands"""
        embed = discord.Embed(
            title="Silcas Bot Commando's",
            description="Hier zijn alle beschikbare commando's:",
            color=0xff3333  # Red color
        )
        
        # Add utility commands section
        embed.add_field(
            name="🛠️ UTILITY COMMANDO'S",
            value="Algemene commando's voor bot beheer",
            inline=False
        )
        
        embed.add_field(
            name="ℹ️ `/help`", 
            value="Toon dit helpbericht met alle beschikbare commando's",
            inline=False
        )
        
        embed.add_field(
            name="🏓 `/ping`", 
            value="Test of de bot werkt en toon de latency",
            inline=False
        )
        
        embed.add_field(
            name="⚙️ `/sync [guild_only]`", 
            value="Synchroniseer slash commands met Discord om ze zichtbaar te maken",
            inline=False
        )
        
        embed.add_field(
            name="🔄 `/refresh`", 
            value="Vernieuw de bot om codewijzigingen toe te passen zonder opnieuw op te starten (alleen voor admins)",
            inline=False
        )
        
        # Add moderation commands section
        embed.add_field(
            name="🛡️ MODERATIE COMMANDO'S",
            value="Commando's voor server moderatie",
            inline=False
        )
        
        embed.add_field(
            name="🔨 `/ban @user [reden]`", 
            value="Verban een gebruiker van de server (vereist ban-rechten)",
            inline=False
        )
        
        embed.add_field(
            name="🔓 `/unban [user_id] [reden]`", 
            value="Verwijder een ban van een gebruiker (vereist ban-rechten)",
            inline=False
        )
        
        embed.add_field(
            name="🔇 `/mute @user [duur] [reden]`", 
            value="Tijdelijk een gebruiker muten in de server (vereist moderate-rechten)",
            inline=False
        )
        
        embed.add_field(
            name="🔊 `/unmute @user`", 
            value="Verwijder een mute van een gebruiker (vereist moderate-rechten)",
            inline=False
        )
        
        embed.add_field(
            name="⏱️ `/timeout @user [duur] [reden]`", 
            value="Tijdelijk een gebruiker een timeout geven (vereist moderate-rechten)",
            inline=False
        )
        
        embed.add_field(
            name="⏰ `/untimeout @user`", 
            value="Verwijder een timeout van een gebruiker (vereist moderate-rechten)",
            inline=False
        )
        
        # Add security commands section
        embed.add_field(
            name="🔒 VEILIGHEID COMMANDO'S",
            value="Commando's voor het scannen van content",
            inline=False
        )
        
        embed.add_field(
            name="🔍 `/scanlink [url]`", 
            value="Scan een URL op mogelijke gevaren",
            inline=False
        )
        
        embed.add_field(
            name="🖼️ `/scanmedia [bijlage]`", 
            value="Scan een afbeelding of video op ongepaste inhoud",
            inline=False
        )
        
        # Add troubleshooting section
        embed.add_field(
            name="❓ PROBLEMEN OPLOSSEN",
            value="Hulp bij veelvoorkomende problemen",
            inline=False
        )
        
        embed.add_field(
            name="📋 Slash Commands Niet Zichtbaar?", 
            value="1. Gebruik `/sync` om commands te synchroniseren\n"
                  "2. Controleer of de bot de juiste scopes heeft (bot EN applications.commands)\n"
                  "3. Het kan tot een uur duren voordat globale commands zichtbaar worden",
            inline=False
        )
        
        # Add legal information section
        embed.add_field(
            name="📜 JURIDISCHE INFORMATIE",
            value="Silcas Bot respecteert je privacy en rechten. Bekijk onze juridische documenten:",
            inline=False
        )
        
        embed.add_field(
            name="🔒 Privacy Beleid",
            value="Bekijk ons [Privacy Beleid](https://github.com/silcasbot/PRIVACY_POLICY.md) voor informatie over hoe we met je gegevens omgaan.",
            inline=True
        )
        
        embed.add_field(
            name="⚖️ Gebruiksvoorwaarden",
            value="Bekijk onze [Gebruiksvoorwaarden](https://github.com/silcasbot/TERMS_OF_SERVICE.md) voor de regels voor het gebruik van de bot.",
            inline=True
        )
        
        # Add footer
        embed.set_footer(text="Gebruik / om commando's te gebruiken | Silcas Bot v1.0")
        
        return embed
    
    # Add a prefix version of the help command
    @bot.command(name="help")
    async def help_command_prefix(ctx):
        """Show all available commands (prefix version)"""
        print(f"[COMMAND] Help command (prefix) executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        embed = create_help_embed()
        
        # Log the commands that should be available
        print(f"[HELP] Showing help with the following commands:")
        for cmd in bot.tree.get_commands():
            print(f"[HELP]   - /{cmd.name}: {cmd.description}")
        
        await ctx.send(embed=embed)
        print(f"[HELP] Help message sent to {ctx.author}")
    
    # Add a slash command version of the help command
    @bot.tree.command(name="help", description="Toon alle beschikbare commando's")
    async def help_command_slash(interaction: discord.Interaction):
        """Show all available commands (slash version)"""
        print(f"[SLASH] Help command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
        
        embed = create_help_embed()
        
        # Log the commands that should be available
        print(f"[HELP] Showing help with the following commands:")
        for cmd in bot.tree.get_commands():
            print(f"[HELP]   - /{cmd.name}: {cmd.description}")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
        print(f"[HELP] Help message sent to {interaction.user}")
    
    # Add a general error handler for all commands
    @bot.event
    async def on_command_error(ctx, error):
        print(f"[ERROR] Command error in {ctx.command if ctx.command else 'unknown command'} from {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        if isinstance(error, commands.MissingPermissions):
            print(f"[ERROR] User lacks required permissions: {error.missing_permissions}")
            await send_temp_message(ctx, f"❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Ontbrekende permissies: {', '.join(error.missing_permissions)}")
        elif isinstance(error, commands.CommandNotFound):
            # Don't respond to unknown commands
            print(f"[ERROR] Command not found: {ctx.message.content}")
            pass
        elif isinstance(error, commands.MissingRequiredArgument):
            print(f"[ERROR] Missing required argument: {error.param.name}")
            await send_temp_message(ctx, f"❌ Ontbrekend argument: {error.param.name}. Gebruik het commando op de juiste manier.")
        elif isinstance(error, commands.BadArgument):
            print(f"[ERROR] Bad argument: {error}")
            await send_temp_message(ctx, "❌ Ongeldig argument. Controleer of je de juiste waarden hebt opgegeven.")
        elif isinstance(error, commands.CommandOnCooldown):
            print(f"[ERROR] Command on cooldown, retry after {error.retry_after:.1f} seconds")
            await send_temp_message(ctx, f"⏳ Dit commando heeft een cooldown. Probeer het opnieuw over {error.retry_after:.1f} seconden.")
        else:
            # Log the error
            print(f"[ERROR] Unhandled command error: {error}")
            
            # Only send detailed error messages if it's not already handled
            if not hasattr(error, 'handled'):
                await send_temp_message(ctx, f"❌ Er is een fout opgetreden bij het uitvoeren van dit commando: {str(error)}")
    
    @bot.event
    async def on_ready():
        print("\n┌─────────────────────────────────────────────────────┐")
        print("│               ✅ BOT SUCCESVOL GESTART                │")
        print("└─────────────────────────────────────────────────────┘")
        
        print(f"\n[BOT] 🤖 {bot.user.name} is nu online en actief!")
        print(f"[BOT] 🆔 Bot ID: {bot.user.id}")
        print(f"[BOT] 🌐 Verbonden met {len(bot.guilds)} servers:")
        
        # Print server information in a table-like format
        if bot.guilds:
            print("\n┌─────────────────────────────────────────────────────────────────────────┐")
            print("│ SERVER NAAM                 │ SERVER ID           │ AANTAL LEDEN         │")
            print("├─────────────────────────────┼─────────────────────┼─────────────────────┤")
            for guild in bot.guilds:
                name = guild.name[:25].ljust(25)
                guild_id = str(guild.id).ljust(15)
                members = str(guild.member_count).ljust(15)
                print(f"│ {name} │ {guild_id} │ {members} │")
            print("└─────────────────────────────┴─────────────────────┴─────────────────────┘")
        
        print("\n[BOT] 🔄 Synchroniseren van slash commands met Discord...")
        try:
            # List all commands that will be synced
            commands_list = bot.tree.get_commands()
            command_names = [f"/{cmd.name}" for cmd in commands_list]
            
            print("\n[BOT] 📋 Beschikbare commands:")
            for cmd_name in command_names:
                print(f"[BOT]   ├─ {cmd_name}")
            
            # Only sync to the first guild to avoid rate limits
            if bot.guilds:
                first_guild = bot.guilds[0]
                print(f"\n[BOT] 🔄 Synchroniseren naar server: {first_guild.name} (ID: {first_guild.id})...")
                await bot.tree.sync(guild=first_guild)
                print(f"[BOT] ✅ Slash commands succesvol gesynchroniseerd naar {first_guild.name}!")
                print(f"[BOT] ℹ️ Gebruik het /synchroniseren")
                print(f"[BOT] ⚠️ Let op: globaal synchroniseren heeft rate limits van Discord")
            else:
                print(f"[BOT] ❌ Geen servers beschikbaar voor het synchroniseren van commando om commands globaal te sync commands")
        except Exception as e:
            print(f"[BOT] ❌ Fout bij synchroniseren van slash commands: {e}")
            print(f"[BOT] ℹ️ Je moet mogelijk handmatig het /sync commando uitvoeren")
        
        # Check bot permissions in all guilds
        print("\n[BOT] 🔍 Controleren van bot permissies in alle servers...")
        missing_permissions = []
        
        for guild in bot.guilds:
            bot_member = guild.get_member(bot.user.id)
            if bot_member:
                # Check for essential permissions
                permission_issues = []
                
                if not bot_member.guild_permissions.moderate_members:
                    missing_permissions.append((guild, "moderate_members"))
                    permission_issues.append("Moderate Members")
                
                if not bot_member.guild_permissions.ban_members:
                    missing_permissions.append((guild, "ban_members"))
                    permission_issues.append("Ban Members")
                
                if not bot_member.guild_permissions.manage_messages:
                    missing_permissions.append((guild, "manage_messages"))
                    permission_issues.append("Manage Messages")
                
                if permission_issues:
                    print(f"[BOT] ⚠️ WAARSCHUWING: Ontbrekende permissies in {guild.name}:")
                    for perm in permission_issues:
                        print(f"[BOT]   ├─ {perm}")
                else:
                    print(f"[BOT] ✅ Alle benodigde permissies aanwezig in {guild.name}")
        
        # Send messages to guild owners about missing permissions
        if missing_permissions:
            print("\n[BOT] ⚠️ BELANGRIJKE WAARSCHUWING: Ontbrekende permissies gedetecteerd!")
            print("[BOT] 📨 Server eigenaren worden geïnformeerd via DM...")
            
            # Group missing permissions by guild
            guild_permissions = {}
            for guild, permission in missing_permissions:
                if guild not in guild_permissions:
                    guild_permissions[guild] = []
                guild_permissions[guild].append(permission)
            
            # Send DMs to guild owners
            for guild, permissions in guild_permissions.items():
                try:
                    if guild.owner:
                        permission_text = "\n".join([f"• {p.replace('_', ' ').title()}" for p in permissions])
                        
                        # Create a more visually appealing message
                        await guild.owner.send(
                            f"# ⚠️ BELANGRIJKE MELDING: Ontbrekende Bot Permissies\n\n"
                            f"De Silcas Bot mist essentiële permissies in **{guild.name}**!\n\n"
                            f"## 🔍 Ontbrekende permissies:\n{permission_text}\n\n"
                            f"## 🛠️ Hoe los je dit op:\n"
                            f"1. Ga naar **Server Instellingen** > **Rollen**\n"
                            f"2. Klik op de rol van de bot\n"
                            f"3. Schakel de ontbrekende permissies in\n\n"
                            f"## 🔄 Alternatieve oplossing:\n"
                            f"Je kunt de bot ook opnieuw uitnodigen met de juiste permissies via het Discord Developer Portal.\n\n"
                            f"## 📞 Hulp nodig?\n"
                            f"Neem contact op met de bot ontwikkelaar voor assistentie."
                        )
                        print(f"[BOT] ✅ DM gestuurd naar eigenaar van {guild.name}")
                except Exception as e:
                    print(f"[BOT] ❌ Kon geen DM sturen naar eigenaar van {guild.name}: {e}")
        
        # Register slash commands
        try:
            print("[SLASH] Registering slash commands...")
            
            # Clear existing commands first to avoid duplicates
            print("[SLASH] Clearing existing commands...")
            bot.tree.clear_commands(guild=None)
            
            # Make sure all commands are properly defined before syncing
            print("[SLASH] Ensuring all commands are properly defined...")
            
            # Manually register all slash commands to ensure they're properly defined
            # This is a safety measure to make sure all commands are registered
            print("[SLASH] Manually registering all slash commands...")
            
            # We don't need to do anything here since the commands are already defined with decorators
            # This is just a checkpoint to ensure all commands are properly loaded
            
            # List all commands that should be available
            print("[SLASH] Commands that will be registered:")
            for cmd in bot.tree.get_commands():
                print(f"[SLASH]   - /{cmd.name}: {cmd.description}")
            
            # Sync commands globally with Discord
            print("[SLASH] Syncing commands globally...")
            await bot.tree.sync()
            print("[SLASH] Slash commands have been registered globally!")
            
            # Also sync to each guild individually to ensure immediate updates
            for guild in bot.guilds:
                try:
                    print(f"[SLASH] Syncing commands to guild: {guild.name} (ID: {guild.id})...")
                    await bot.tree.sync(guild=guild)
                    print(f"[SLASH] Slash commands have been registered for guild: {guild.name}")
                except Exception as guild_e:
                    print(f"[SLASH ERROR] Failed to register slash commands for guild {guild.name}: {guild_e}")
            
            # Log to database
            import dashboard_db as db
            db.log_system_event(
                event_type="Bot Startup",
                details="Bot is gestart en slash commands zijn geregistreerd"
            )
            
            print("[SLASH] All slash commands have been registered successfully!")
            
            # Print important information about scopes
            print("\n[SLASH] ⚠️ IMPORTANT INFORMATION ABOUT SLASH COMMANDS ⚠️")
            print("[SLASH] If commands are not visible in Discord, check the following:")
            print("[SLASH] 1. Make sure the bot has BOTH the 'bot' AND 'applications.commands' scopes")
            print("[SLASH] 2. To fix this, go to Discord Developer Portal > OAuth2 > URL Generator")
            print("[SLASH] 3. Select BOTH 'bot' and 'applications.commands' scopes")
            print("[SLASH] 4. Select the necessary bot permissions")
            print("[SLASH] 5. Use the generated URL to reinvite the bot to your server")
            print("[SLASH] 6. Try using the /sync command in Discord")
            print("[SLASH] 7. Note that it may take up to an hour for global commands to appear")
            print("[SLASH] 8. Guild-specific commands should appear immediately after syncing")
            print("[SLASH] ⚠️ WITHOUT THE 'applications.commands' SCOPE, SLASH COMMANDS WILL NOT WORK! ⚠️\n")
            
        except Exception as e:
            print(f"[SLASH ERROR] Failed to register slash commands: {e}")
        
        # Start the moderation check task
        bot.loop.create_task(check_moderation_actions())
        
    # Keep the original prefix command for backward compatibility
    @bot.command(name="refresh")
    @commands.has_permissions(administrator=True)
    async def refresh_bot_prefix(ctx):
        """Refresh the bot to apply code changes without restarting"""
        await perform_refresh(ctx)
    
    # Add the slash command version
    @bot.tree.command(name="refresh", description="Vernieuw de bot om codewijzigingen toe te passen zonder opnieuw op te starten")
    async def refresh_bot_slash(interaction: discord.Interaction):
        """Refresh the bot to apply code changes without restarting"""
        # Check if user has admin permissions
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("❌ Je hebt geen toestemming om deze opdracht uit te voeren. Alleen administrators kunnen de bot vernieuwen.", ephemeral=True)
            return
        
        # Create a context-like object for the refresh function
        class SlashContext:
            def __init__(self, interaction):
                self.interaction = interaction
                self.author = interaction.user
                self.responded = False
            
            async def send(self, content):
                if not self.responded:
                    await self.interaction.response.send_message(content)
                    self.responded = True
                else:
                    await self.interaction.followup.send(content)
        
        ctx = SlashContext(interaction)
        await perform_refresh(ctx)
    
    # Shared function for both prefix and slash commands
    async def perform_refresh(ctx):
        try:
            # Send a confirmation message
            refresh_msg = await ctx.send("🔄 Bot wordt vernieuwd... Dit kan enkele seconden duren.")
            
            # Log the refresh action
            print(f"[REFRESH] Bot refresh aangevraagd door {ctx.author} ({ctx.author.id})")
            
            # Reload modules
            import importlib
            import sys
            
            # List of modules to reload (add more if needed)
            modules_to_reload = [
                'dashboard_db',
                # Add other modules here if needed
            ]
            
            # Reload each module
            for module_name in modules_to_reload:
                if module_name in sys.modules:
                    importlib.reload(sys.modules[module_name])
                    print(f"[REFRESH] Module {module_name} is opnieuw geladen")
            
            # Update the database connection
            import dashboard_db as db
            db.init_db()
            
            # Re-sync slash commands
            try:
                # Clear existing commands first to avoid duplicates
                bot.tree.clear_commands(guild=None)
                
                # Sync commands globally with Discord
                await bot.tree.sync()
                print("[REFRESH] Slash commands zijn globaal opnieuw gesynchroniseerd")
                
                # Also sync to each guild individually to ensure immediate updates
                for guild in bot.guilds:
                    try:
                        await bot.tree.sync(guild=guild)
                        print(f"[REFRESH] Slash commands zijn opnieuw gesynchroniseerd voor guild: {guild.name}")
                    except Exception as guild_e:
                        print(f"[WARNING] Kon slash commands niet synchroniseren voor guild {guild.name}: {guild_e}")
            except Exception as e:
                print(f"[WARNING] Kon slash commands niet synchroniseren: {e}")
            
            # Try to delete the initial message
            try:
                await refresh_msg.delete()
            except:
                pass
                
            # Send success message that will auto-delete after 10 seconds
            await send_temp_message(ctx, "✅ Bot is vernieuwd! Nieuwe code is nu actief.")
            
            # Log success
            print("[REFRESH] Bot refresh voltooid")
            
            # Log to database
            db.log_system_event(
                event_type="Bot Refresh",
                user_id=str(ctx.author.id),
                username=str(ctx.author),
                details="Bot refresh via command"
            )
            
        except Exception as e:
            # Send error message
            await send_temp_message(ctx, f"❌ Fout bij vernieuwen van de bot: {e}")
            print(f"[ERROR] Fout bij bot refresh: {e}")
    
    # Keep the original prefix command for backward compatibility
    @bot.command(name="ban")
    @commands.has_permissions(ban_members=True)
    async def ban_user_prefix(ctx, member: discord.Member = None, *, reason="Geen reden opgegeven"):
        """Ban a user and log it to the database"""
        print(f"[COMMAND] Ban command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        if member is None:
            print(f"[BAN] No member specified")
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te verbannen. Gebruik: `/ban @gebruiker [reden]`")
            return
        print(f"[BAN] Attempting to ban {member} (ID: {member.id}) for reason: {reason}")
        await perform_ban(ctx, member, reason)
        
    # Error handler for the ban command
    @ban_user_prefix.error
    async def ban_error(ctx, error):
        print(f"[ERROR] Command error in ban from {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'} channel")
        if isinstance(error, commands.MissingPermissions):
            print(f"[ERROR] User lacks required permissions: {error.missing_permissions}")
            
            # Create a more user-friendly error message
            await send_temp_message(ctx, "❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Je hebt de 'Leden Verbannen' (Ban Members) permissie nodig om gebruikers te verbannen.")
        elif isinstance(error, commands.MissingRequiredArgument):
            print(f"[ERROR] Missing required argument: {error.param.name}")
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te verbannen. Gebruik: `/ban @gebruiker [reden]`")
        elif isinstance(error, commands.BadArgument):
            print(f"[ERROR] Bad argument: {error}")
            await send_temp_message(ctx, "❌ Kon de opgegeven gebruiker niet vinden. Zorg ervoor dat je een geldige gebruiker vermeldt.")
        else:
            print(f"[ERROR] Unhandled error in ban command: {error}")
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(error)}")
    
    # Add the slash command version
    @bot.tree.command(name="ban", description="Verban een gebruiker van de server")
    @discord.app_commands.describe(
        member="De gebruiker die je wilt verbannen",
        reason="De reden voor de verbanning"
    )
    async def ban_user_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "Geen reden opgegeven"):
        """Ban a user and log it to the database"""
        try:
            # Check if user has ban permissions
            if not interaction.user.guild_permissions.ban_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om gebruikers te verbannen. Je hebt de 'Ban Members' permissie nodig.", ephemeral=True)
                return
            
            # Create a context-like object for the ban function
            class SlashContext:
                def __init__(self, interaction):
                    self.interaction = interaction
                    self.author = interaction.user
                    self.guild = interaction.guild
                    self.responded = False
                
                async def send(self, content):
                    if not self.responded:
                        await self.interaction.response.send_message(content)
                        self.responded = True
                    else:
                        await self.interaction.followup.send(content)
            
            ctx = SlashContext(interaction)
            await perform_ban(ctx, member, reason)
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for ban command: {e}")
            print(f"Error in ban slash command: {e}")
    
    # Shared function for both prefix and slash commands
    async def perform_ban(ctx, member, reason):
        try:
            print(f"[BAN] Starting ban process for {member} (ID: {member.id})")
            # Check if the bot has permission to ban members
            if not ctx.guild.me.guild_permissions.ban_members:
                print(f"[BAN ERROR] Bot lacks 'Ban Members' permission in {ctx.guild.name}")
                await send_temp_message(ctx, "❌ De bot heeft geen toestemming om gebruikers te verbannen. Geef de bot de 'Ban Members' permissie.")
                return
                
            # Check if the member is bannable (e.g., not the owner, not higher role than bot)
            # Check if the member is the server owner
            if member.id == ctx.guild.owner_id:
                print(f"[BAN ERROR] Cannot ban {member} - user is the server owner")
                await send_temp_message(ctx, f"❌ Kan {member.mention} niet verbannen omdat deze gebruiker de eigenaar van de server is.")
                return
                
            # Check if the member's highest role is higher than the bot's highest role
            if member.top_role >= ctx.guild.me.top_role:
                print(f"[BAN ERROR] Cannot ban {member} - user has higher or equal role than the bot")
                await send_temp_message(ctx, f"❌ Kan {member.mention} niet verbannen. Deze gebruiker heeft een hogere of gelijke rol dan de bot.")
                return
                
            # Ban the user
            print(f"[BAN] Executing ban for {member}")
            await member.ban(reason=reason)
            print(f"[BAN] Successfully banned {member}")
            
            # Log ban to database
            print(f"[BAN] Logging ban to database")
            import dashboard_db as db
            db.log_ban(
                user_id=str(member.id),
                username=str(member),
                guild_id=str(ctx.guild.id),
                guild_name=ctx.guild.name,
                reason=reason
            )
            print(f"[BAN] Ban logged to database")
            
            # Send confirmation message that will auto-delete after 10 seconds
            await send_temp_message(ctx, f"✅ Gebruiker {member.mention} is verbannen. Reden: {reason}")
            
            # Log to mod channel
            print(f"[BAN] Logging violation to mod channel")
            await log_violation(member, f"Handmatige ban door {ctx.author}", "Manual Ban", reason)
            print(f"[BAN] Ban process completed successfully")
            
        except discord.errors.Forbidden:
            print(f"[BAN ERROR] Forbidden error when trying to ban {member} - missing permissions")
            await send_temp_message(ctx, "❌ De bot heeft geen toestemming om deze actie uit te voeren. Controleer de bot permissies.")
        except Exception as e:
            print(f"[BAN ERROR] Failed to ban user {member}: {e}")
            await send_temp_message(ctx, f"❌ Fout bij verbannen van gebruiker: {e}")
    
    @bot.event
    async def on_message(message):
        # Ignore messages from the bot itself
        if message.author == bot.user:
            return
            
        # Log message details (but not content for privacy)
        channel_name = message.channel.name if hasattr(message.channel, 'name') else "DM"
        guild_name = message.guild.name if message.guild else "DM"
        print(f"[MESSAGE] Message from {message.author} in {guild_name}/{channel_name}")
    
        # Check for buffer overflow patterns
        for pattern in BOF_PATTERNS:
            if pattern in message.content:
                print(f"[SECURITY] Buffer overflow pattern detected from {message.author} in {guild_name}/{channel_name}")
                try:
                    print(f"[SECURITY] Deleting message with buffer overflow pattern")
                    await message.delete()
                    print(f"[SECURITY] Message deleted successfully")
                    
                    # Create a visually appealing warning embed
                    embed = discord.Embed(
                        title="⚠️ Stack Buffer Overflow Gedetecteerd",
                        description=f"Er is potentieel gevaarlijke code gedetecteerd en verwijderd.",
                        color=0xFF3333  # Red color
                    )
                    embed.add_field(name="Gebruiker", value=message.author.mention, inline=True)
                    embed.add_field(name="Actie", value="Bericht verwijderd + Timeout", inline=True)
                    embed.add_field(
                        name="Informatie", 
                        value="Het delen van stack buffer overflow-gerelateerde code is niet toegestaan in deze server. "
                              "Deze code kan gebruikt worden voor kwaadaardige doeleinden en vormt een beveiligingsrisico.",
                        inline=False
                    )
                    embed.set_footer(text="Automatische moderatie door Silcas Bot • Dit bericht verdwijnt na 10 seconden")
                    
                    # Send the warning and set it to delete after 10 seconds
                    warning_msg = await message.channel.send(embed=embed)
                    print(f"[SECURITY] Warning message sent")
                    
                    # Delete warning after 10 seconds
                    await warning_msg.delete(delay=10)
                    
                    print(f"[SECURITY] Applying timeout to {message.author}")
                    await timeout_user(message.author, message.guild)
                    print(f"[SECURITY] Logging violation")
                    await log_violation(message.author, message.content, "Stack Buffer Overflow")
                    print(f"[SECURITY] Security measures applied successfully")
                    return
                except Exception as e:
                    print(f'[SECURITY ERROR] Error processing buffer overflow pattern: {e}')
                    return
        
        # Check for URLs in the message
        urls = re.findall(URL_PATTERN, message.content)
        if urls:
            print(f"[URL] Found {len(urls)} URLs in message from {message.author}")
            for url in urls:
                # Make sure URL has proper http/https prefix
                if url.startswith('www.'):
                    url = 'https://' + url
                
                print(f"[URL] Scanning URL: {url[:50]}...")
                is_malicious, scan_result, threat_level = await scan_url(url)
                print(f"[URL] Scan result: {'MALICIOUS' if is_malicious else 'SAFE'} - Threat Level: {threat_level} - {scan_result}")
                
                # Log all URLs, regardless of whether they're malicious
                print(f"[URL] Logging URL scan to database with threat level: {threat_level}")
                await log_url_scan(message.author, url, is_malicious, scan_result, threat_level)
                
                # Only take action if the URL is malicious
                if is_malicious:
                    print(f"[SECURITY] Malicious URL detected from {message.author}")
                    try:
                        print(f"[SECURITY] Deleting message with malicious URL")
                        await message.delete()
                        print(f"[SECURITY] Message deleted successfully")
                        
                        # Get threat level
                        _, _, threat_level = await scan_url(url)
                        
                        # Set colors and icons based on threat level
                        threat_colors = {
                            "low": 0xFFCC00,      # Yellow
                            "medium": 0xFF9900,   # Orange
                            "high": 0xFF3300,     # Dark Orange
                            "critical": 0xFF0000  # Red
                        }
                        
                        threat_icons = {
                            "low": "⚠️",
                            "medium": "⚠️",
                            "high": "🚨",
                            "critical": "☣️"
                        }
                        
                        threat_descriptions = {
                            "low": "mogelijk verdacht",
                            "medium": "verdacht",
                            "high": "gevaarlijk",
                            "critical": "zeer gevaarlijk"
                        }
                        
                        color = threat_colors.get(threat_level, 0xFF0000)
                        icon = threat_icons.get(threat_level, "⚠️")
                        description = threat_descriptions.get(threat_level, "verdacht")
                        
                        # Create a visually appealing warning message with details about the threat
                        embed = discord.Embed(
                            title=f"{icon} {description.upper()} LINK GEDETECTEERD",
                            description=f"Een {description} link is verwijderd voor de veiligheid van alle gebruikers.",
                            color=color
                        )
                        
                        # Add a thumbnail based on threat type
                        if "IP Logger" in scan_result:
                            embed.set_thumbnail(url="https://i.imgur.com/JWxMJmV.png")  # IP tracking icon
                        elif "Malware" in scan_result:
                            embed.set_thumbnail(url="https://i.imgur.com/GnyVSAd.png")  # Virus icon
                        elif "Phishing" in scan_result:
                            embed.set_thumbnail(url="https://i.imgur.com/QKpyYiY.png")  # Phishing icon
                        elif "NSFW" in scan_result:
                            embed.set_thumbnail(url="https://i.imgur.com/JzOSQXk.png")  # NSFW icon
                        elif "Cryptocurrency" in scan_result:
                            embed.set_thumbnail(url="https://i.imgur.com/8bYkxXt.png")  # Crypto scam icon
                        else:
                            embed.set_thumbnail(url="https://i.imgur.com/YkqVKfM.png")  # General warning icon
                        
                        # Add user information with avatar
                        embed.add_field(name="👤 Gebruiker", value=message.author.mention, inline=True)
                        embed.add_field(name="📝 Kanaal", value=message.channel.mention, inline=True)
                        embed.set_author(name=f"{message.author.display_name}", icon_url=message.author.display_avatar.url)
                        
                        # Add detection details with formatting
                        embed.add_field(name="🔍 Detectie Details", value=f"```{scan_result}```", inline=False)
                        
                        # Add information about the threat with more details
                        threat_info = ""
                        if "IP Logger" in scan_result:
                            threat_info += "• **IP Logger**: Deze link kan je IP-adres en locatie stelen.\n"
                        if "Malware" in scan_result:
                            threat_info += "• **Malware**: Deze link kan schadelijke software bevatten.\n"
                        if "Phishing" in scan_result:
                            threat_info += "• **Phishing**: Deze link probeert mogelijk je inloggegevens te stelen.\n"
                        if "NSFW" in scan_result:
                            threat_info += "• **NSFW Content**: Deze link bevat mogelijk ongepaste inhoud.\n"
                        if "Obfuscated" in scan_result:
                            threat_info += "• **Verborgen Link**: Deze link gebruikt technieken om zijn ware doel te verbergen.\n"
                        if "Cryptocurrency" in scan_result:
                            threat_info += "• **Crypto Scam**: Deze link is mogelijk een cryptocurrency-oplichting.\n"
                        if "Suspicious" in scan_result:
                            threat_info += "• **Verdachte Link**: Deze link vertoont verdacht gedrag.\n"
                        
                        if not threat_info:
                            threat_info = "Deze link is als gevaarlijk gemarkeerd door ons beveiligingssysteem."
                            
                        embed.add_field(
                            name="⚠️ Waarschuwing", 
                            value=threat_info,
                            inline=False
                        )
                        
                        # Add safety tips
                        embed.add_field(
                            name="🛡️ Veiligheidstips", 
                            value="• Klik nooit op verdachte links\n"
                                  "• Deel geen persoonlijke informatie\n"
                                  "• Gebruik een wachtwoordmanager\n"
                                  "• Houd je software up-to-date",
                            inline=False
                        )
                        
                        # Add footer with timestamp
                        embed.set_footer(text="Silcas Bot Beveiligingssysteem • Deze waarschuwing verdwijnt over 30 seconden")
                        embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
                        
                        # Send the warning message
                        warning_msg = await message.channel.send(embed=embed)
                        print(f"[SECURITY] Enhanced warning message sent")
                        
                        # Delete warning after 30 seconds
                        await warning_msg.delete(delay=30)
                        
                        # Log the violation with threat level
                        await log_violation(
                            user=message.author, 
                            content=f"Malicious URL: {url}", 
                            violation_type="Malicious URL", 
                            scan_result=scan_result,
                            threat_level=threat_level,
                            additional_info=f"URL detected in channel: {message.channel.name} ({message.channel.id})"
                        )
                        
                        # Apply timeout to the user
                        print(f"[SECURITY] Applying timeout to {message.author}")
                        await timeout_user(message.author, message.guild, reason=f"Malicious URL detected: {scan_result}")
                        print(f"[SECURITY] Security measures applied successfully")
                        return
                    except Exception as e:
                        print(f'[SECURITY ERROR] Error processing malicious URL: {e}')
                        return
        
        # Check for image and video attachments
        if message.attachments:
            for attachment in message.attachments:
                # Scan the attachment for NSFW content
                is_nsfw, scan_result, content_type = await scan_media_content(attachment)
                
                # Determine threat level based on scan result
                media_threat_level = "low"  # Default for safe content
                if is_nsfw:
                    media_threat_level = "medium"  # Default for NSFW
                    if "nudity: high" in scan_result.lower() or "explicit: high" in scan_result.lower():
                        media_threat_level = "high"
                    elif "gore" in scan_result.lower() or "violence" in scan_result.lower():
                        media_threat_level = "critical"
                
                # Log all media scans with threat level
                print(f"[MEDIA SCAN] Logging media scan to database with threat level: {media_threat_level}")
                await log_media_scan(message.author, attachment.url, is_nsfw, scan_result, content_type, media_threat_level)
                
                # Only take action if the media is NSFW
                if is_nsfw:
                    try:
                        # Delete the message with inappropriate media
                        await message.delete()
                        
                        # Create a visually appealing warning embed
                        embed = discord.Embed(
                            title="⚠️ Ongepaste Media Gedetecteerd",
                            description=f"Er is ongepaste media gedetecteerd en verwijderd.",
                            color=0xFF3333  # Red color
                        )
                        embed.add_field(name="Gebruiker", value=message.author.mention, inline=True)
                        embed.add_field(name="Actie", value="Bericht verwijderd + Timeout", inline=True)
                        embed.add_field(
                            name="Informatie", 
                            value="Het delen van ongepaste of NSFW media is niet toegestaan in deze server. "
                                  "Bij herhaalde overtredingen kunnen strengere maatregelen worden genomen.",
                            inline=False
                        )
                        embed.set_footer(text="Automatische moderatie door Silcas Bot • Dit bericht verdwijnt na 10 seconden")
                        
                        # Send the warning and set it to delete after 10 seconds
                        warning_msg = await message.channel.send(embed=embed)
                        await warning_msg.delete(delay=10)
                        
                        # Apply timeout and log the violation with enhanced details
                        await timeout_user(message.author, message.guild, reason="Ongepaste media gedetecteerd")
                        
                        # Determine threat level based on scan result
                        nsfw_threat_level = "medium"  # Default
                        if "nudity: high" in scan_result.lower() or "explicit: high" in scan_result.lower():
                            nsfw_threat_level = "high"
                        elif "gore" in scan_result.lower() or "violence" in scan_result.lower():
                            nsfw_threat_level = "critical"
                            
                        # Log with enhanced information
                        await log_violation(
                            user=message.author, 
                            content=f"NSFW Media: {attachment.url}", 
                            violation_type="NSFW Media", 
                            scan_result=scan_result,
                            threat_level=nsfw_threat_level,
                            additional_info=f"Media type: {content_type}, Detected in channel: {message.channel.name} ({message.channel.id})"
                        )
                        return
                    except Exception as e:
                        print(f'Fout bij verwerken van bericht met ongepaste media: {e}')
                        return
    
        # Process commands
        await bot.process_commands(message)
    
    async def timeout_user(user, guild, reason="Overtreding van serverregels gedetecteerd"):
        print(f"[TIMEOUT] Starting timeout process for {user} in {guild.name}")
        try:
            member = guild.get_member(user.id)
            if not member:
                print(f"[TIMEOUT ERROR] Could not find user {user.id} in server {guild.name}")
                return False
                
            # Check if the bot has permission to moderate members
            bot_member = guild.get_member(bot.user.id)
            if not bot_member.guild_permissions.moderate_members:
                print(f"[TIMEOUT ERROR] ⚠️ BOT LACKS PERMISSIONS: Bot does not have 'Moderate Members' permission in {guild.name}!")
                print("[TIMEOUT ERROR] Go to Server Settings > Roles > [Bot Role] > Permissions and enable 'Moderate Members'.")
                
                # Try to send a message to the guild owner
                try:
                    if guild.owner:
                        print(f"[TIMEOUT] Attempting to send DM to server owner {guild.owner}")
                        await guild.owner.send(f"⚠️ **BELANGRIJKE MELDING**: De bot heeft geen 'Moderate Members' permissie in **{guild.name}**!\n\n"
                                              f"Hierdoor kan de bot geen timeouts toepassen op gebruikers die de regels overtreden.\n\n"
                                              f"**Hoe los je dit op:**\n"
                                              f"1. Ga naar Server Instellingen > Rollen\n"
                                              f"2. Klik op de rol van de bot\n"
                                              f"3. Schakel de permissie 'Leden modereren' in\n\n"
                                              f"Als je hulp nodig hebt, neem contact op met de bot ontwikkelaar.")
                        print(f"[TIMEOUT] DM sent to server owner")
                except Exception as dm_error:
                    print(f"[TIMEOUT ERROR] Could not send DM to server owner: {dm_error}")
                
                return False
                
            # Check if the member can be timed out (e.g., not the owner, not higher role than bot)
            if not member.timed_out_until is None and member.timed_out_until > datetime.datetime.now(datetime.UTC):
                print(f"[TIMEOUT] User {user} is already timed out until {member.timed_out_until}")
                return False
                
            if member.guild_permissions.administrator:
                print(f"[TIMEOUT ERROR] Cannot timeout user {user} because they have administrator permissions")
                return False
                
            # Calculate timeout end time
            timeout_until = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=TIMEOUT_DURATION)
            print(f"[TIMEOUT] Calculated timeout until: {timeout_until}")
            
            try:
                # Apply timeout
                print(f"[TIMEOUT] Applying timeout to {user} for {TIMEOUT_DURATION/86400} days")
                await member.timeout(datetime.timedelta(seconds=TIMEOUT_DURATION), reason=reason)
                print(f"[TIMEOUT] Successfully applied timeout to {user} - Reason: {reason}")
                
                # Log timeout to database
                print(f"[TIMEOUT] Logging timeout to database")
                import dashboard_db as db
                db.log_timeout(
                    user_id=str(user.id),
                    username=str(user),
                    guild_id=str(guild.id),
                    guild_name=guild.name,
                    timeout_until=timeout_until.isoformat(),
                    reason=reason
                )
                print(f"[TIMEOUT] Timeout logged to database")
                return True
            except discord.errors.Forbidden:
                print(f"[TIMEOUT ERROR] ⚠️ PERMISSION ERROR: Cannot timeout user {user} in {guild.name}. Bot does not have enough rights.")
                print("[TIMEOUT ERROR] Make sure the bot role is higher in the role list than the user's role and that the bot has 'Moderate Members' permission.")
                return False
        except Exception as e:
            print(f'[TIMEOUT ERROR] Error timing out user {user}: {e}')
            return False
    
    async def scan_url(url):
        """
        Enhanced comprehensive URL scanner that checks for various threats:
        - Malware and phishing (via VirusTotal)
        - IP loggers and IP grabbers
        - NSFW content
        - Known malicious domains
        - Obfuscated malicious URLs
        - Scam and phishing patterns
        
        Returns a tuple (is_malicious, scan_result, threat_level)
        where threat_level is one of: 'low', 'medium', 'high', 'critical'
        """
        print(f"[URL SCAN] Starting enhanced comprehensive scan of URL: {url}")
        
        # Initialize result variables
        is_malicious = False
        scan_result = ""
        threat_types = []
        threat_level = "low"  # Default threat level
        
        # 1. Define comprehensive lists of malicious domains
        
        # 1.1 Known IP logger domains (massive list)
        ip_logger_domains = [
            # Common IP loggers
            "grabify.link", "iplogger.org", "iplogger.com", "iplogger.ru", "2no.co",
            "ipgrabber.ru", "ipgraber.ru", "iplis.ru", "02ip.ru", "ezstat.ru",
            "whatismyipaddress.com", "grabify.icu", "iplist.ru", "iplogger.co",
            "iplogger.info", "ipgrabber.com", "trackip.net", "ip-tracker.org",
            "ps3cfw.com", "logger.pro", "webresolver.nl", "blasze.com", "blasze.tk",
            "catsnthing.com", "catsnthings.fun", "yip.su", "yip.ee", "yip.fi",
            "fuglekos.com", "grabify.org", "leancoding.co", "stopify.co",
            "freegiftcards.co", "joinmy.site", "curiouscat.club", "lovebird.guru",
            "trulove.guru", "dateing.club", "shrekis.life", "headshot.monster",
            "gaming-at-my.best", "progaming.monster", "yourmy.monster", "imageshare.best",
            "screenshot.best", "gamingfun.me", "catsnthing.com", "catsnthings.fun",
            "url-cut.com", "url-cut.org", "gyazo.nl", "gyazo.co", "gyazo.in",
            "spottyfly.com", "spötify.com", "discörd.com", "minecräft.com",
            "quickmessage.us", "top-gaming.pro", "fortnight.space", "fortnitechat.site",
            "youshouldclick.us", "youtubeshort.pro", "youtubeshort.site", "youtubeshort.space",
            "crabrave.pw", "särahah.eu", "särahah.pl", "xda-developers.us",
            "starbucksiswrong.com", "starbucksisbadforyou.com", "bucks.as",
            "myprivate.pics", "imageshare.best", "screenshot.best", "gamingfun.me",
            "partpicker.shop", "sportshub.bar", "locations.quest", "twitchstats.net",
            
            # Additional IP loggers
            "iplogger.app", "2ip.ru", "iplogger.at", "iplogger.co.uk", "iplogger.tv",
            "iplogger.net", "iplogger.biz", "iplogger.io", "iplogger.site", "iplogger.blog",
            "ipgrabber.io", "ipgrabber.org", "ipgrabber.net", "ipgrabber.me", "ipgrabber.site",
            "ip-grabber.com", "ip-grabber.org", "ip-grabber.net", "ip-grabber.me", "ip-grabber.site",
            "ip-logger.com", "ip-logger.org", "ip-logger.net", "ip-logger.me", "ip-logger.site",
            "grabify.com", "grabify.me", "grabify.net", "grabify.org", "grabify.site",
            "iptrack.io", "iptracker.site", "iptracker.org", "iptracker.net", "iptracker.me",
            "iptracker.app", "iptracker.co", "iptracker.info", "iptracker.biz", "iptracker.tv",
            "ipfinder.me", "ipfinder.io", "ipfinder.site", "ipfinder.org", "ipfinder.net",
            "ipfinder.app", "ipfinder.co", "ipfinder.info", "ipfinder.biz", "ipfinder.tv",
            "iphunter.net", "iphunter.org", "iphunter.io", "iphunter.site", "iphunter.me",
            "iphunter.app", "iphunter.co", "iphunter.info", "iphunter.biz", "iphunter.tv",
            "ipsnatcher.com", "ipsnatcher.org", "ipsnatcher.net", "ipsnatcher.me", "ipsnatcher.site",
            "ipsnatcher.app", "ipsnatcher.co", "ipsnatcher.info", "ipsnatcher.biz", "ipsnatcher.tv",
            "ipsniff.com", "ipsniff.org", "ipsniff.net", "ipsniff.me", "ipsniff.site",
            "ipsniff.app", "ipsniff.co", "ipsniff.info", "ipsniff.biz", "ipsniff.tv",
            "ipspy.net", "ipspy.org", "ipspy.io", "ipspy.site", "ipspy.me",
            "ipspy.app", "ipspy.co", "ipspy.info", "ipspy.biz", "ipspy.tv",
            "ipscraper.com", "ipscraper.org", "ipscraper.net", "ipscraper.me", "ipscraper.site",
            "ipscraper.app", "ipscraper.co", "ipscraper.info", "ipscraper.biz", "ipscraper.tv",
            "ipstealer.com", "ipstealer.org", "ipstealer.net", "ipstealer.me", "ipstealer.site",
            "ipstealer.app", "ipstealer.co", "ipstealer.info", "ipstealer.biz", "ipstealer.tv",
            "ipgrab.org", "ipgrab.io", "ipgrab.me", "ipgrab.site", "ipgrab.net",
            "ipgrab.app", "ipgrab.co", "ipgrab.info", "ipgrab.biz", "ipgrab.tv",
            "iplocation.net", "iplocation.io", "iplocation.site", "iplocation.org", "iplocation.me",
            "iplocation.app", "iplocation.co", "iplocation.info", "iplocation.biz", "iplocation.tv",
            "iptracker.xyz", "ipgrabber.xyz", "iplogger.xyz", "ipfinder.xyz", "ipsnatcher.xyz",
            "ipstealer.xyz", "ipspy.xyz", "ipscraper.xyz", "ipgrab.xyz", "iplocation.xyz",
            
            # New additions - more IP loggers
            "whatismyip.com", "whatismyip.org", "whatismyip.net",
            "findmyip.org", "findmyip.net", "findmyip.com", "findmyip.io", "findmyip.app",
            "myip.com", "myip.org", "myip.net", "myip.io", "myip.app", "myip.site",
            "checkip.org", "checkip.net", "checkip.com", "checkip.io", "checkip.app",
            "ipchecker.net", "ipchecker.org", "ipchecker.com", "ipchecker.io", "ipchecker.app",
            "ipcheck.net", "ipcheck.org", "ipcheck.com", "ipcheck.io", "ipcheck.app",
            "ipdetect.net", "ipdetect.org", "ipdetect.com", "ipdetect.io", "ipdetect.app",
            "ipdetector.net", "ipdetector.org", "ipdetector.com", "ipdetector.io", "ipdetector.app",
            "ipreveal.net", "ipreveal.org", "ipreveal.com", "ipreveal.io", "ipreveal.app",
            "iprevealer.net", "iprevealer.org", "iprevealer.com", "iprevealer.io", "iprevealer.app",
            "ipshow.net", "ipshow.org", "ipshow.com", "ipshow.io", "ipshow.app",
            "ipshower.net", "ipshower.org", "ipshower.com", "ipshower.io", "ipshower.app",
            "ipview.net", "ipview.org", "ipview.com", "ipview.io", "ipview.app",
            "ipviewer.net", "ipviewer.org", "ipviewer.com", "ipviewer.io", "ipviewer.app",
            "ipwatch.net", "ipwatch.org", "ipwatch.com", "ipwatch.io", "ipwatch.app",
            "ipwatcher.net", "ipwatcher.org", "ipwatcher.com", "ipwatcher.io", "ipwatcher.app",
            "seeip.net", "seeip.org", "seeip.com", "seeip.io", "seeip.app",
            "seeyourip.net", "seeyourip.org", "seeyourip.com", "seeyourip.io", "seeyourip.app",
            "showip.net", "showip.org", "showip.com", "showip.io", "showip.app",
            "showyourip.net", "showyourip.org", "showyourip.com", "showyourip.io", "showyourip.app",
            "viewip.net", "viewip.org", "viewip.com", "viewip.io", "viewip.app",
            "viewyourip.net", "viewyourip.org", "viewyourip.com", "viewyourip.io", "viewyourip.app",
            "watchip.net", "watchip.org", "watchip.com", "watchip.io", "watchip.app",
            "watchyourip.net", "watchyourip.org", "watchyourip.com", "watchyourip.io", "watchyourip.app"
        ]
        
        # 1.2 Known malware and virus domains
        malware_domains = [
            # Malware distribution domains
            "malware.wicar.org", "rogue.bank-secure.com", "secure.bank-secure.com", "virus-detector.com",
            "antivirus-scanner.com", "system-update.info", "windows-update.info", "flash-player-update.com",
            "adobe-update.com", "java-update.info", "browser-update.info", "chrome-update.online",
            "firefox-update.online", "edge-update.online", "safari-update.online", "opera-update.online",
            "browser-security.online", "system-security.online", "windows-security.online", "mac-security.online",
            "android-security.online", "ios-security.online", "device-security.online", "computer-security.online",
            "phone-security.online", "tablet-security.online", "laptop-security.online", "desktop-security.online"
        ]
        
        # 1.3 URL shorteners that might hide malicious links
        suspicious_url_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs", "pic.gd", "DwarfURL.com",
            "ow.ly", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "tr.im", "twit.ac",
            "su.pr", "twurl.nl", "snipurl.com", "short.to", "BudURL.com", "ping.fm", "post.ly",
            "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com", "twitthis.com",
            "htxt.it", "AltURL.com", "RedirX.com", "DigBig.com", "short.ie", "u.mavrev.com",
            "kl.am", "wp.me", "u.nu", "rubyurl.com", "om.ly", "linkbee.com", "Yep.it", "posted.at",
            "xrl.us", "metamark.net", "sn.im", "hurl.ws", "eepurl.com", "idek.net", "urlpire.com",
            "chilp.it", "moourl.com", "snurl.com", "xr.com", "lin.cr", "EasyURI.com", "zz.gd",
            "ur1.ca", "URL.ie", "adjix.com", "cutt.us", "u.to", "YSat.me", "Profile.to",
            "ub0.cc", "minurl.fr", "shrinkify.com", "ri.ms", "b23.ru", "Fly2.ws", "xrl.in",
            "Fhurl.com", "wipi.es", "korta.nu", "shortna.me", "fa.b", "WapURL.co.uk", "urlcut.com"
        ]
        
        # Extract domain and path from URL for analysis
        try:
            from urllib.parse import urlparse, unquote
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = unquote(parsed_url.path.lower())
            query = unquote(parsed_url.query.lower())
            full_url_lower = url.lower()
            
            # Remove www. if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # 2. Enhanced URL scanning with multiple checks
            
            # 2.1 Check for IP logger domains (comprehensive list)
            if domain in ip_logger_domains:
                is_malicious = True
                threat_types.append("IP Logger")
                threat_level = "critical"  # IP loggers are a critical threat
                print(f"[URL SCAN] Detected known IP logger domain: {domain}")
            
            # 2.2 Check for malware domains
            if domain in malware_domains:
                is_malicious = True
                threat_types.append("Malware Domain")
                threat_level = "critical"
                print(f"[URL SCAN] Detected known malware domain: {domain}")
            
            # 2.3 Check for URL shorteners (potentially hiding malicious content)
            if domain in suspicious_url_shorteners:
                print(f"[URL SCAN] Detected URL shortener: {domain}")
                # We don't mark it as malicious automatically, but we increase the threat level
                # if Safe Mode is enabled with high threshold
                
                # Check if Safe Mode is enabled
                import dashboard_db as db
                safe_mode_enabled = db.is_safe_mode_enabled()
                safe_mode_threshold = db.get_safe_mode_threshold()
                
                if safe_mode_enabled and safe_mode_threshold == 'high':
                    is_malicious = True
                    threat_types.append("URL Shortener")
                    threat_level = max(threat_level, "medium")
                    print(f"[URL SCAN] URL shortener marked as malicious due to Safe Mode high threshold")
                
            # Check for lookalike domains (homograph attacks)
            popular_domains = {
                "discord": ["discörd", "dıscord", "discоrd", "discогd", "dіscord", "discordapp"],
                "steam": ["stеam", "steаm", "steamcommunity", "steampowered"],
                "paypal": ["pаypal", "paypаl", "paypаl", "paypаl.com", "paypal-secure"],
                "microsoft": ["micrоsoft", "microsоft", "microsоft", "microsоft.com"],
                "google": ["googlе", "googlе.com", "googlе-secure"],
                "facebook": ["facеbook", "facebоok", "faceboоk", "faceboоk.com"],
                "instagram": ["instаgram", "instаgram.com", "instаgram-secure"],
                "twitter": ["twittеr", "twittеr.com", "twittеr-secure"],
                "amazon": ["amazоn", "amazоn.com", "amazоn-secure"],
                "apple": ["applе", "applе.com", "applе-secure"],
                "netflix": ["nеtflix", "nеtflix.com", "nеtflix-secure"],
                "twitch": ["twitсh", "twitсh.tv", "twitсh-secure"],
                "youtube": ["youtubе", "youtubе.com", "youtubе-secure"],
                "whatsapp": ["whatsаpp", "whatsаpp.com", "whatsаpp-secure"],
                "tiktok": ["tiktоk", "tiktоk.com", "tiktоk-secure"],
                "snapchat": ["snapchаt", "snapchаt.com", "snapchаt-secure"],
                "reddit": ["rеddit", "rеddit.com", "rеddit-secure"],
                "linkedin": ["linkеdin", "linkеdin.com", "linkеdin-secure"],
                "github": ["github", "githаb.com", "githаb-secure"],
                "yahoo": ["yahоo", "yahоo.com", "yahоo-secure"],
                "spotify": ["spоtify", "spоtify.com", "spоtify-secure"]
            }
            
            for brand, lookalikes in popular_domains.items():
                for lookalike in lookalikes:
                    if lookalike in domain and brand not in domain:
                        is_malicious = True
                        threat_types.append(f"Lookalike Domain ({brand})")
                        threat_level = max(threat_level, "high")
                        print(f"[URL SCAN] Detected lookalike domain: {domain} mimicking {brand}")
            
            # Check for obfuscation techniques
            obfuscation_patterns = [
                r"data:text/html",  # Data URI scheme
                r"javascript:",     # JavaScript URI
                r"\\x[0-9a-f]{2}",  # Hex encoding
                r"%[0-9a-f]{2}",    # URL encoding
                r"&#[0-9]+;",       # HTML entity encoding
                r"base64",          # Base64 encoding
                r"\\u[0-9a-f]{4}"   # Unicode escape sequences
            ]
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, full_url_lower):
                    is_malicious = True
                    threat_types.append("Obfuscated URL")
                    threat_level = max(threat_level, "high")
                    print(f"[URL SCAN] Detected obfuscation technique: {pattern}")
                    break
                    
            # Check for suspicious URL patterns
            suspicious_patterns = [
                # Existing patterns
                r"login\.php",              # Phishing login pages
                r"account.*?verify",        # Account verification phishing
                r"secure.*?login",          # Fake secure login
                r"password.*?reset",        # Password reset phishing
                r"confirm.*?account",       # Account confirmation phishing
                r"update.*?account",        # Account update phishing
                r"verify.*?identity",       # Identity verification phishing
                r"authenticate",            # Authentication phishing
                r"wallet.*?connect",        # Crypto wallet phishing
                r"authenticate.*?device",   # Device authentication phishing
                r"signin.*?required",       # Sign-in required phishing
                r"security.*?alert",        # Security alert phishing
                r"unusual.*?activity",      # Unusual activity phishing
                r"suspicious.*?login",      # Suspicious login phishing
                r"account.*?suspended",     # Account suspended phishing
                r"account.*?disabled",      # Account disabled phishing
                r"account.*?locked",        # Account locked phishing
                r"free.*?nitro",            # Discord Nitro scams
                r"steam.*?gift",            # Steam gift scams
                r"free.*?robux",            # Roblox scams
                r"free.*?vbucks",           # Fortnite V-Bucks scams
                r"free.*?coins",            # Free coins scams
                r"free.*?money",            # Free money scams
                r"giveaway.*?discord",      # Discord giveaway scams
                r"claim.*?prize",           # Prize claim scams
                r"claim.*?reward",          # Reward claim scams
                r"download.*?hack",         # Hack download scams
                r"cheat.*?download",        # Cheat download scams
                r"generator.*?online",      # Online generator scams
                r"hack.*?generator",        # Hack generator scams
                r"free.*?download.*?hack",  # Free hack download scams
                r"free.*?premium",          # Free premium scams
                r"cracked.*?account",       # Cracked account scams
                r"account.*?generator",     # Account generator scams
                r"token.*?grabber",         # Token grabber scams
                r"token.*?logger",          # Token logger scams
                r"nitro.*?generator",       # Nitro generator scams
                r"nitro.*?free",            # Free Nitro scams
                r"gift.*?card.*?generator", # Gift card generator scams
                r"credit.*?card.*?generator", # Credit card generator scams
                
                # Additional phishing patterns
                r"login.*?required",            # Login required phishing
                r"account.*?security",          # Account security phishing
                r"account.*?alert",             # Account alert phishing
                r"account.*?warning",           # Account warning phishing
                r"account.*?notice",            # Account notice phishing
                r"account.*?validate",          # Account validation phishing
                r"account.*?authenticate",      # Account authentication phishing
                r"account.*?authorize",         # Account authorization phishing
                r"account.*?verification",      # Account verification phishing
                r"account.*?validation",        # Account validation phishing
                r"account.*?authentication",    # Account authentication phishing
                r"account.*?authorization",     # Account authorization phishing
                r"account.*?recovery",          # Account recovery phishing
                r"account.*?restore",           # Account restore phishing
                r"account.*?reset",             # Account reset phishing
                r"account.*?unlock",            # Account unlock phishing
                r"account.*?reactivate",        # Account reactivation phishing
                r"account.*?reactive",          # Account reactivation phishing
                r"account.*?renew",             # Account renewal phishing
                r"account.*?renewal",           # Account renewal phishing
                r"account.*?expire",            # Account expiration phishing
                r"account.*?expiration",        # Account expiration phishing
                r"account.*?limit",             # Account limit phishing
                r"account.*?limitation",        # Account limitation phishing
                r"account.*?restrict",          # Account restriction phishing
                r"account.*?restriction",       # Account restriction phishing
                r"account.*?block",             # Account block phishing
                r"account.*?blocked",           # Account blocked phishing
                r"account.*?suspend",           # Account suspension phishing
                
                # Additional Discord-specific phishing
                r"discord.*?nitro.*?free",      # Free Discord Nitro scams
                r"nitro.*?gift",                # Nitro gift scams
                r"gift.*?nitro",                # Nitro gift scams
                r"discord.*?gift",              # Discord gift scams
                r"gift.*?discord",              # Discord gift scams
                r"discord.*?airdrop",           # Discord airdrop scams
                r"airdrop.*?discord",           # Discord airdrop scams
                r"discord.*?drop",              # Discord drop scams
                r"drop.*?discord",              # Discord drop scams
                r"discord.*?token",             # Discord token scams
                r"token.*?discord",             # Discord token scams
                r"token.*?stealer",             # Token stealer scams
                
                # Additional gaming-related scams
                r"gift.*?steam",                # Steam gift scams
                r"steam.*?key",                 # Steam key scams
                r"key.*?steam",                 # Steam key scams
                r"steam.*?code",                # Steam code scams
                r"code.*?steam",                # Steam code scams
                r"steam.*?wallet",              # Steam wallet scams
                r"wallet.*?steam",              # Steam wallet scams
                r"steam.*?card",                # Steam card scams
                r"card.*?steam",                # Steam card scams
                r"steam.*?giveaway",            # Steam giveaway scams
                r"giveaway.*?steam",            # Steam giveaway scams
                r"steam.*?free",                # Free Steam scams
                r"free.*?steam",                # Free Steam scams
                r"robux.*?generator",           # Robux generator scams
                r"generator.*?robux",           # Robux generator scams
                r"vbucks.*?generator",          # V-Bucks generator scams
                r"generator.*?vbucks",          # V-Bucks generator scams
                r"fortnite.*?free",             # Free Fortnite scams
                r"free.*?fortnite",             # Free Fortnite scams
                r"fortnite.*?generator",        # Fortnite generator scams
                r"generator.*?fortnite",        # Fortnite generator scams
                r"minecraft.*?free",            # Free Minecraft scams
                r"free.*?minecraft",            # Free Minecraft scams
                r"minecraft.*?generator",       # Minecraft generator scams
                r"generator.*?minecraft",       # Minecraft generator scams
                r"roblox.*?free",               # Free Roblox scams
                r"free.*?roblox",               # Free Roblox scams
                r"roblox.*?generator",          # Roblox generator scams
                r"generator.*?roblox",          # Roblox generator scams
                
                # Additional financial scams
                r"generator.*?gift.*?card",     # Gift card generator scams
                r"generator.*?credit.*?card",   # Credit card generator scams
                r"paypal.*?money.*?generator",  # PayPal money generator scams
                r"generator.*?paypal.*?money",  # PayPal money generator scams
                r"bitcoin.*?generator",         # Bitcoin generator scams
                r"generator.*?bitcoin",         # Bitcoin generator scams
                r"ethereum.*?generator",        # Ethereum generator scams
                r"generator.*?ethereum",        # Ethereum generator scams
                r"crypto.*?generator",          # Crypto generator scams
                r"generator.*?crypto",          # Crypto generator scams
                r"money.*?generator",           # Money generator scams
                r"generator.*?money",           # Money generator scams
                r"cash.*?generator",            # Cash generator scams
                r"generator.*?cash",            # Cash generator scams
                r"money.*?free",                # Free money scams
                r"cash.*?free",                 # Free cash scams
                r"free.*?bitcoin",              # Free Bitcoin scams
                r"bitcoin.*?free",              # Free Bitcoin scams
                r"free.*?ethereum",             # Free Ethereum scams
                r"ethereum.*?free",             # Free Ethereum scams
                r"free.*?crypto",               # Free crypto scams
                r"crypto.*?free",               # Free crypto scams
                r"double.*?your.*?bitcoin",     # Double your Bitcoin scams
                r"bitcoin.*?double",            # Bitcoin doubling scams
                r"double.*?your.*?ethereum",    # Double your Ethereum scams
                r"ethereum.*?double",           # Ethereum doubling scams
                r"double.*?your.*?crypto",      # Double your crypto scams
                r"crypto.*?double",             # Crypto doubling scams
                r"double.*?your.*?money",       # Double your money scams
                r"money.*?double",              # Money doubling scams
                r"double.*?your.*?cash",        # Double your cash scams
                r"cash.*?double",               # Cash doubling scams
                
                # Additional software/malware related
                r"crack.*?download",            # Crack download scams
                r"download.*?crack",            # Crack download scams
                r"keygen.*?download",           # Keygen download scams
                r"download.*?keygen",           # Keygen download scams
                r"serial.*?download",           # Serial download scams
                r"download.*?serial",           # Serial download scams
                r"patch.*?download",            # Patch download scams
                r"download.*?patch",            # Patch download scams
                r"hack.*?download",             # Hack download scams
                r"free.*?software",             # Free software scams
                r"software.*?free",             # Free software scams
                r"free.*?license",              # Free license scams
                r"license.*?free",              # Free license scams
                r"free.*?key",                  # Free key scams
                r"key.*?free",                  # Free key scams
                r"free.*?code",                 # Free code scams
                r"code.*?free",                 # Free code scams
                r"free.*?activation",           # Free activation scams
                r"activation.*?free",           # Free activation scams
                r"free.*?serial",               # Free serial scams
                r"serial.*?free",               # Free serial scams
                r"free.*?keygen",               # Free keygen scams
                r"keygen.*?free",               # Free keygen scams
                r"free.*?crack",                # Free crack scams
                r"crack.*?free"                 # Free crack scams
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, path) or re.search(pattern, query):
                    is_malicious = True
                    threat_types.append("Suspicious URL Pattern")
                    threat_level = max(threat_level, "medium")
                    print(f"[URL SCAN] Detected suspicious URL pattern: {pattern}")
                    break
                    
        except Exception as e:
            print(f"[URL SCAN] Error parsing and analyzing URL: {e}")
        
        # 2. Check for URL shorteners (potential risk)
        url_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs", "ow.ly",
            "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc", "cutt.ly",
            "shorturl.at", "tiny.one", "tinyurl.io", "clck.ru", "short.io", "rb.gy",
            "rebrand.ly", "snip.ly", "snipurl.com", "tr.im", "urlz.fr", "x.co",
            "yourls.org", "z.pe", "v.gd", "qr.net", "1url.com", "tweez.me", "v.ht",
            "tgig.ir", "7.ly", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp",
            "buzurl.com", "cutt.us", "u.bb", "yourls.org", "prettylinkpro.com",
            "scrnch.me", "filoops.info", "vzturl.com", "qr.ae", "adcraft.co",
            "vurl.com", "adcrun.ch", "adv.li", "vk.cc", "gkurl.us", "shrt.li",
            "ln.is", "soo.gd", "s2r.co", "clicky.me", "budurl.com", "bc.vc",
            "dai.ly", "db.tt", "kl.am", "qps.ru", "dft.ba", "goo.su", "n9.cl",
            "gg.gg", "cort.as", "tny.im", "msft.it", "wp.me", "fw.io", "u.nu"
        ]
        
        if domain in url_shorteners:
            # URL shorteners aren't automatically malicious, but they're suspicious
            print(f"[URL SCAN] Detected URL shortener: {domain}")
            threat_types.append("URL Shortener")
            threat_level = max(threat_level, "medium")
            
            # In Safe Mode with high threshold, treat URL shorteners as malicious
            if safe_mode_enabled and safe_mode_threshold == 'high':
                is_malicious = True
                threat_level = "high"
                print(f"[URL SCAN] URL shortener marked as malicious due to Safe Mode high threshold")
        
        # Check if Safe Mode is enabled
        import dashboard_db as db
        safe_mode_enabled = db.is_safe_mode_enabled()
        safe_mode_threshold = db.get_safe_mode_threshold()
        
        # 3. Check for NSFW keywords in URL
        # Basic NSFW keywords (always checked)
        nsfw_keywords = [
            "porn", "xxx", "sex", "adult", "nude", "naked", "pussy", "cock", "penis",
            "vagina", "boobs", "tits", "ass", "anal", "cum", "blowjob", "handjob",
            "masturbation", "orgasm", "dildo", "vibrator", "hentai", "nsfw", "xvideos",
            "pornhub", "xnxx", "xhamster", "redtube", "youporn", "brazzers", "onlyfans",
            "chaturbate", "livejasmin", "stripchat", "bongacams", "cam4", "myfreecams",
            "camsoda", "flirt4free", "streamate", "adultfriendfinder", "xvideos2",
            "xnxx2", "pornhub2", "xhamster2", "redtube2", "youporn2", "brazzers2",
            "onlyfans2", "chaturbate2", "livejasmin2", "stripchat2", "bongacams2",
            "cam42", "myfreecams2", "camsoda2", "flirt4free2", "streamate2",
            "adultfriendfinder2", "xvideos3", "xnxx3", "pornhub3", "xhamster3",
            "redtube3", "youporn3", "brazzers3", "onlyfans3", "chaturbate3",
            "livejasmin3", "stripchat3", "bongacams3", "cam43", "myfreecams3",
            "camsoda3", "flirt4free3", "streamate3", "adultfriendfinder3"
        ]
        
        # Additional keywords for Safe Mode
        if safe_mode_enabled:
            print(f"[URL SCAN] Safe Mode is ENABLED with {safe_mode_threshold} threshold")
            
            # Add more keywords based on Safe Mode threshold
            if safe_mode_threshold == 'medium' or safe_mode_threshold == 'high':
                nsfw_keywords.extend([
                    "dating", "hookup", "sexy", "hot", "18+", "mature", "fetish", 
                    "escort", "sugar", "webcam", "cam", "strip", "erotic", "erotica",
                    "adult", "xxx", "porn", "nsfw", "nude", "naked", "sex", "sexy",
                    "hot", "18+", "mature", "fetish", "escort", "sugar", "webcam",
                    "cam", "strip", "erotic", "erotica", "adult", "xxx", "porn",
                    "nsfw", "nude", "naked", "sex", "sexy", "hot", "18+", "mature",
                    "fetish", "escort", "sugar", "webcam", "cam", "strip", "erotic",
                    "erotica", "adult", "xxx", "porn", "nsfw", "nude", "naked", "sex"
                ])
                
            if safe_mode_threshold == 'high':
                nsfw_keywords.extend([
                    "bikini", "lingerie", "swimsuit", "model", "massage", "tinder",
                    "bumble", "grindr", "dating", "date", "kiss", "intimate", "flirt",
                    "love", "romance", "relationship", "partner", "boyfriend", "girlfriend",
                    "husband", "wife", "spouse", "marriage", "wedding", "engagement",
                    "proposal", "anniversary", "honeymoon", "divorce", "breakup",
                    "single", "bachelor", "bachelorette", "crush", "admirer", "lover",
                    "affair", "cheat", "infidelity", "unfaithful", "faithful", "loyal",
                    "disloyal", "commitment", "casual", "hookup", "one-night", "stand",
                    "fling", "friends-with-benefits", "fwb", "booty", "call", "ex",
                    "former", "past", "current", "future", "potential", "prospective",
                    "match", "compatible", "incompatible", "chemistry", "spark", "attraction",
                    "attractive", "unattractive", "hot", "sexy", "cute", "handsome",
                    "beautiful", "gorgeous", "pretty", "ugly", "plain", "average",
                    "ordinary", "extraordinary", "exceptional", "special", "unique",
                    "rare", "common", "uncommon", "unusual", "usual", "normal", "abnormal",
                    "weird", "strange", "odd", "peculiar", "bizarre", "eccentric",
                    "quirky", "different", "similar", "alike", "unlike", "distinct",
                    "distinctive", "characteristic", "trait", "quality", "attribute",
                    "feature", "aspect", "element", "component", "part", "piece",
                    "section", "segment", "portion", "fraction", "whole", "complete",
                    "incomplete", "partial", "full", "empty", "half", "quarter",
                    "third", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth"
                ])
        else:
            print("[URL SCAN] Safe Mode is DISABLED, using default keywords")
        
        url_lower = url.lower()
        for keyword in nsfw_keywords:
            if keyword in url_lower:
                is_malicious = True
                threat_types.append("NSFW Content")
                threat_level = max(threat_level, "medium")
                print(f"[URL SCAN] Detected NSFW keyword in URL: {keyword}")
                break
        
        # 4. Check for VirusTotal results if API key is available
        if VIRUSTOTAL_API_KEY:
            try:
                # Encode the URL
                url_id = requests.utils.quote(url, safe='')
                headers = {
                    "x-apikey": VIRUSTOTAL_API_KEY
                }
                
                # First check if the URL has already been analyzed
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers
                )
                
                # If the URL hasn't been analyzed yet, submit it for analysis
                if response.status_code == 404:
                    # Submit URL for analysis
                    data = {"url": url}
                    response = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data=data
                    )
                    
                    if response.status_code != 200:
                        print(f"[URL SCAN] Error submitting URL to VirusTotal: {response.status_code}")
                    else:
                        # Wait a moment for analysis to complete
                        url_id = response.json().get("data", {}).get("id", "")
                        if not url_id:
                            print("[URL SCAN] Could not get analysis ID from VirusTotal")
                        else:
                            # Give VT some time to analyze
                            import time
                            time.sleep(3)
                            
                            # Get analysis results
                            response = requests.get(
                                f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                                headers=headers
                            )
                
                if response.status_code == 200:
                    # Process results
                    result = response.json()
                    stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                    
                    # If any engine detected it as malicious
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    if malicious > 0 or suspicious > 0:
                        is_malicious = True
                        if malicious > 0:
                            threat_types.append(f"Malware/Phishing ({malicious} detecties)")
                            # Set threat level based on number of detections
                            if malicious >= 5:
                                threat_level = "critical"
                            elif malicious >= 3:
                                threat_level = max(threat_level, "high")
                            else:
                                threat_level = max(threat_level, "medium")
                        if suspicious > 0:
                            threat_types.append(f"Suspicious ({suspicious} detecties)")
                            threat_level = max(threat_level, "medium")
                        
                        print(f"[URL SCAN] VirusTotal results - Malicious: {malicious}, Suspicious: {suspicious}")
                else:
                    print(f"[URL SCAN] Error getting results from VirusTotal: {response.status_code}")
            
            except Exception as e:
                print(f"[URL SCAN] Error in VirusTotal scan: {e}")
        else:
            print("[URL SCAN] VirusTotal API key not configured, skipping malware check")
        
        # 5. Check for scam TLDs (top-level domains)
        suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".pw", ".cc", ".club",
            ".work", ".dating", ".racing", ".win", ".bid", ".stream", ".party", ".review",
            ".trade", ".accountant", ".download", ".loan", ".cricket", ".faith", ".science",
            ".icu", ".buzz", ".monster", ".online", ".site", ".website", ".space", ".fun",
            ".uno", ".host", ".press", ".tech", ".live", ".life", ".store", ".click",
            ".link", ".email", ".cloud", ".today", ".digital", ".agency", ".world", ".best",
            ".network", ".guru", ".info", ".biz", ".mobi", ".name", ".pro", ".travel",
            ".shop", ".app", ".blog", ".design", ".dev", ".game", ".games", ".software",
            ".studio", ".technology", ".tools", ".zone", ".media", ".news", ".photos",
            ".pictures", ".video", ".videos", ".audio", ".music", ".band", ".chat",
            ".community", ".social", ".team", ".group", ".company", ".business", ".market",
            ".marketing", ".sale", ".discount", ".deal", ".promo", ".promotion", ".win",
            ".winner", ".prize", ".award", ".rewards", ".bonus", ".free", ".gratis",
            ".gift", ".present", ".giveaway", ".contest", ".competition", ".lottery",
            ".bet", ".bets", ".casino", ".poker", ".game", ".play", ".player", ".gaming",
            ".sport", ".sports", ".team", ".club", ".fan", ".fans", ".supporter", ".vip"
        ]
        
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                print(f"[URL SCAN] Detected suspicious TLD: {tld}")
                if "Suspicious Domain" not in threat_types:
                    threat_types.append("Suspicious Domain")
                    threat_level = max(threat_level, "low")
                break
        
        # 6. Check for cryptocurrency scams
        crypto_keywords = [
            "bitcoin", "ethereum", "crypto", "wallet", "blockchain", "token", "coin",
            "mining", "miner", "btc", "eth", "ltc", "xrp", "doge", "binance", "coinbase",
            "metamask", "trustwallet", "ledger", "trezor", "airdrop", "giveaway", "free",
            "double", "multiply", "investment", "invest", "profit", "earn", "mining",
            "miner", "pool", "stake", "staking", "yield", "farm", "farming", "defi",
            "nft", "token", "ico", "presale", "pre-sale", "sale", "launch", "drop"
        ]
        
        crypto_scam_patterns = [
            r"free.*?bitcoin", r"bitcoin.*?giveaway", r"eth.*?giveaway", 
            r"double.*?bitcoin", r"double.*?eth", r"multiply.*?crypto",
            r"crypto.*?giveaway", r"wallet.*?connect", r"wallet.*?validation",
            r"wallet.*?verify", r"wallet.*?sync", r"metamask.*?connect",
            r"trustwallet.*?connect", r"ledger.*?connect", r"trezor.*?connect",
            r"airdrop.*?claim", r"claim.*?airdrop", r"free.*?nft", 
            r"nft.*?giveaway", r"nft.*?drop", r"mint.*?free"
        ]
        
        # Check for crypto keywords
        crypto_keyword_found = False
        for keyword in crypto_keywords:
            if keyword in full_url_lower:
                crypto_keyword_found = True
                break
                
        # If crypto keyword found, check for scam patterns
        if crypto_keyword_found:
            for pattern in crypto_scam_patterns:
                if re.search(pattern, full_url_lower):
                    is_malicious = True
                    threat_types.append("Cryptocurrency Scam")
                    threat_level = max(threat_level, "high")
                    print(f"[URL SCAN] Detected cryptocurrency scam pattern: {pattern}")
                    break
        
        # Compile the final result with threat level
        if threat_types:
            threat_level_emoji = {
                "low": "🟢",
                "medium": "🟡",
                "high": "🟠",
                "critical": "🔴"
            }
            
            scan_result = f"{threat_level_emoji[threat_level]} Dreigingsniveau: {threat_level.upper()}\n⚠️ Gedetecteerde bedreigingen: {', '.join(threat_types)}"
        else:
            scan_result = "✅ Geen bedreigingen gedetecteerd"
        
        print(f"[URL SCAN] Scan completed. Result: {'MALICIOUS' if is_malicious else 'SAFE'} - Threat Level: {threat_level} - {scan_result}")
        return is_malicious, scan_result, threat_level
            
    async def scan_media_content(attachment):
        """
        Scan an image or video for NSFW content using SightEngine API.
        Returns a tuple (is_nsfw, scan_result, content_type)
        
        SightEngine API documentation: https://sightengine.com/docs/reference
        """
        if not NSFW_API_KEY:
            print("WAARSCHUWING: Geen NSFW API-sleutel gevonden. Media-scanning is uitgeschakeld.")
            return False, "API-sleutel ontbreekt", "unknown"
            
        try:
            # Determine content type
            filename = attachment.filename.lower()
            content_type = "unknown"
            
            # Check if it's an image
            if any(filename.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']):
                content_type = "image"
            # Check if it's a video
            elif any(filename.endswith(ext) for ext in ['.mp4', '.webm', '.mov', '.avi', '.mkv']):
                content_type = "video"
            else:
                # Not a supported media type
                return False, "Niet-ondersteund bestandstype", content_type
            
            # For SightEngine API, we can directly pass the URL of the attachment
            # This is more efficient than downloading and re-uploading the file
            
            # SightEngine API credentials
            # Note: SightEngine requires both an API user and an API secret
            # The NSFW_API_KEY environment variable should be in the format "user_id:api_secret"
            if ":" not in NSFW_API_KEY:
                print("WAARSCHUWING: NSFW API-sleutel heeft onjuist formaat. Moet 'user_id:api_secret' zijn.")
                return False, "Ongeldige API-sleutel", content_type
                
            api_user, api_secret = NSFW_API_KEY.split(":", 1)
            
            # Prepare the API request parameters
            params = {
                'api_user': api_user,
                'api_secret': api_secret,
                'url': attachment.url,
                'models': 'nudity,wad,offensive,gore'  # Models to check for
            }
            
            # Make the API request
            response = requests.get('https://api.sightengine.com/1.0/check.json', params=params)
            
            # Check if the request was successful
            if response.status_code != 200:
                return False, f"API fout: {response.status_code}", content_type
                
            # Parse the API response
            result = response.json()
            
            # Extract the relevant scores
            nudity_score = result.get('nudity', {}).get('raw', 0)
            offensive_score = result.get('offensive', {}).get('prob', 0)
            gore_score = result.get('gore', {}).get('prob', 0)
            
            # Check if Safe Mode is enabled
            import dashboard_db as db
            safe_mode_enabled = db.is_safe_mode_enabled()
            safe_mode_threshold = db.get_safe_mode_threshold()
            
            # Set thresholds based on Safe Mode settings
            if safe_mode_enabled:
                if safe_mode_threshold == 'low':
                    # Slightly stricter thresholds
                    nudity_threshold = 0.5
                    offensive_threshold = 0.6
                    gore_threshold = 0.4
                elif safe_mode_threshold == 'high':
                    # Very strict thresholds
                    nudity_threshold = 0.3
                    offensive_threshold = 0.4
                    gore_threshold = 0.2
                else:  # medium (default)
                    # Moderately strict thresholds
                    nudity_threshold = 0.4
                    offensive_threshold = 0.5
                    gore_threshold = 0.3
                
                print(f"[MEDIA SCAN] Safe Mode is ENABLED with {safe_mode_threshold} threshold")
            else:
                # Default thresholds (Safe Mode disabled)
                nudity_threshold = 0.6
                offensive_threshold = 0.7
                gore_threshold = 0.5
                print("[MEDIA SCAN] Safe Mode is DISABLED, using default thresholds")
            
            # Determine if the content is NSFW based on the scores and thresholds
            is_nsfw = (nudity_score > nudity_threshold or 
                      offensive_score > offensive_threshold or 
                      gore_score > gore_threshold)
            
            # Create a detailed scan result string
            categories = {
                "nudity": nudity_score,
                "offensive": offensive_score,
                "gore": gore_score,
                "weapon": result.get('weapon', 0),
                "alcohol": result.get('alcohol', 0),
                "drugs": result.get('drugs', 0)
            }
            
            scan_result = ", ".join([f"{cat}: {score:.2f}" for cat, score in categories.items() if score > 0])
            
            return is_nsfw, scan_result, content_type
            
        except Exception as e:
            print(f"Fout bij scannen van media: {e}")
            return False, f"Scan fout: {str(e)}", "unknown"
    
    def get_user_ip_like_identifier(user_id):
        """
        Generate a deterministic IP-like identifier based on the user ID.
        This is NOT a real IP address, but a simulation for logging purposes.
        """
        # Create a hash of the user ID
        hash_object = hashlib.md5(str(user_id).encode())
        hash_hex = hash_object.hexdigest()
        
        # Use the hash to generate IP-like segments
        segments = []
        for i in range(4):
            # Take 2 characters from the hash and convert to a number between 1 and 254
            segment = int(hash_hex[i*2:i*2+2], 16) % 254 + 1
            segments.append(str(segment))
        
        # Join the segments with dots to create an IP-like string
        ip_like = ".".join(segments)
        return ip_like
    
    async def log_url_scan(user, url, is_malicious, scan_result, threat_level="low"):
        """
        Enhanced logging of URL scans to the mod channel and database with more detailed information
        
        Parameters:
        - user: The Discord user who triggered the scan
        - url: The URL that was scanned
        - is_malicious: Whether the URL was detected as malicious
        - scan_result: Results from scanning the URL
        - threat_level: Severity of the threat if malicious ("low", "medium", "high", "critical")
        """
        try:
            # Generate an IP-like identifier for the user
            ip_like = get_user_ip_like_identifier(user.id)
            
            # Get current timestamp for consistent logging
            timestamp = datetime.datetime.now(datetime.timezone.utc)
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Set color and emoji based on threat level and malicious status
            if is_malicious:
                threat_colors = {
                    "low": 0xFFCC00,      # Yellow
                    "medium": 0xFF9900,   # Orange
                    "high": 0xFF3300,     # Dark Orange
                    "critical": 0xFF0000  # Red
                }
                
                threat_emojis = {
                    "low": "⚠️",
                    "medium": "🔶",
                    "high": "🚨",
                    "critical": "☣️"
                }
                
                color = threat_colors.get(threat_level, 0xFF9900)  # Default to orange if unknown
                emoji = threat_emojis.get(threat_level, "⚠️")      # Default to warning if unknown
                status = f"{threat_level.upper()} THREAT"
            else:
                color = discord.Color.green()
                emoji = "✅"
                status = "SAFE"
                threat_level = "none"
            
            # Enhanced console logging
            print(f"[URL SCAN LOG] {formatted_time} | {emoji} {status} | User: {user} (ID: {user.id})")
            print(f"[URL SCAN LOG] URL: {url}")
            print(f"[URL SCAN LOG] Scan Result: {scan_result}")
            
            # Log to Discord channel
            channel = bot.get_channel(MOD_LOG_CHANNEL_ID)
            if channel:
                # Set title based on malicious status
                if is_malicious:
                    title = f"{emoji} MALAFIDE URL GEDETECTEERD - {threat_level.upper()}"
                else:
                    title = f"{emoji} URL SCAN RESULTAAT - VEILIG"
                
                # Create a more detailed and structured description
                description = [
                    f"**Gebruiker:** {user.mention}",
                    f"**Gebruikers-ID:** `{user.id}`",
                    f"**Gebruikersnaam:** `{user}`",
                    f"**IP-achtige ID:** `{ip_like}`",
                    f"**Tijdstip:** `{formatted_time}`",
                    f"**URL:** `{url}`"
                ]
                
                # Add threat level if malicious
                if is_malicious:
                    description.append(f"**Dreigingsniveau:** `{threat_level.upper()}`")
                
                # Add scan result with proper formatting
                description.append(f"**Scan resultaat:** ```{scan_result}```")
                
                # Join all parts with newlines
                full_description = "\n".join(description)
                
                # Create the embed with all the information
                embed = discord.Embed(
                    title=title,
                    description=full_description,
                    color=color,
                    timestamp=timestamp
                )
                
                # Add user avatar as thumbnail
                embed.set_thumbnail(url=user.display_avatar.url)
                
                # Add URL domain information
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    
                    embed.add_field(
                        name="URL Informatie",
                        value=f"**Domain:** `{domain}`\n**Protocol:** `{parsed_url.scheme}`",
                        inline=False
                    )
                except Exception as e:
                    print(f"[URL SCAN LOG] Error parsing URL: {e}")
                
                # Add server information if available
                if hasattr(user, "guild") and user.guild:
                    embed.add_field(
                        name="Server Informatie",
                        value=f"**Naam:** {user.guild.name}\n**ID:** `{user.guild.id}`",
                        inline=False
                    )
                
                # Add footer with bot name
                if is_malicious:
                    embed.set_footer(text=f"Silcas Bot Beveiligingssysteem • Dreigingsniveau: {threat_level.upper()}")
                else:
                    embed.set_footer(text=f"Silcas Bot Beveiligingssysteem • URL geclassificeerd als VEILIG")
                
                # Send the embed to the mod channel
                await channel.send(embed=embed)
                print(f"[URL SCAN LOG] Successfully sent detailed log to mod channel (ID: {MOD_LOG_CHANNEL_ID})")
            else:
                print(f"[URL SCAN LOG] ⚠️ Could not find mod log channel with ID: {MOD_LOG_CHANNEL_ID}")
            
            # Log to database with enhanced information
            db.log_url_scan(
                user_id=user.id,
                username=str(user),
                ip_like=ip_like,
                url=url,
                is_malicious=is_malicious,
                scan_result=scan_result,
                threat_level=threat_level
            )
            print(f"[URL SCAN LOG] Successfully logged URL scan to database")
        except Exception as e:
            print(f'[URL SCAN LOG] ❌ ERROR logging URL scan: {e}')
            import traceback
            traceback.print_exc()
            
    async def log_media_scan(user, media_url, is_nsfw, scan_result, content_type, threat_level="medium"):
        """
        Enhanced logging of media scans to the mod channel and database with more detailed information
        
        Parameters:
        - user: The Discord user who shared the media
        - media_url: URL of the media that was scanned
        - is_nsfw: Whether the media was detected as NSFW
        - scan_result: Results from scanning the media
        - content_type: Type of media content (image, video, etc.)
        - threat_level: Severity of the threat if NSFW ("low", "medium", "high", "critical")
        """
        try:
            # Generate an IP-like identifier for the user
            ip_like = get_user_ip_like_identifier(user.id)
            
            # Get current timestamp for consistent logging
            timestamp = datetime.datetime.now(datetime.timezone.utc)
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Set color and emoji based on NSFW status and threat level
            if is_nsfw:
                threat_colors = {
                    "low": 0xFFCC00,      # Yellow
                    "medium": 0xFF9900,   # Orange
                    "high": 0xFF3300,     # Dark Orange
                    "critical": 0xFF0000  # Red
                }
                
                threat_emojis = {
                    "low": "⚠️",
                    "medium": "🔶",
                    "high": "🚨",
                    "critical": "☣️"
                }
                
                color = threat_colors.get(threat_level, 0xFF9900)  # Default to orange if unknown
                emoji = threat_emojis.get(threat_level, "⚠️")      # Default to warning if unknown
                status = f"{threat_level.upper()} THREAT"
            else:
                color = discord.Color.green()
                emoji = "✅"
                status = "SAFE"
                threat_level = "none"
            
            # Enhanced console logging
            print(f"[MEDIA SCAN LOG] {formatted_time} | {emoji} {status} | User: {user} (ID: {user.id})")
            print(f"[MEDIA SCAN LOG] Media URL: {media_url}")
            print(f"[MEDIA SCAN LOG] Content Type: {content_type}")
            print(f"[MEDIA SCAN LOG] Scan Result: {scan_result}")
            
            # Log to Discord channel
            channel = bot.get_channel(MOD_LOG_CHANNEL_ID)
            if channel:
                # Set title based on NSFW status
                if is_nsfw:
                    title = f"{emoji} ONGEPASTE MEDIA GEDETECTEERD - {threat_level.upper()}"
                else:
                    title = f"{emoji} MEDIA SCAN RESULTAAT - VEILIG"
                
                # Create a more detailed and structured description
                description = [
                    f"**Gebruiker:** {user.mention}",
                    f"**Gebruikers-ID:** `{user.id}`",
                    f"**Gebruikersnaam:** `{user}`",
                    f"**IP-achtige ID:** `{ip_like}`",
                    f"**Tijdstip:** `{formatted_time}`",
                    f"**Media URL:** `{media_url}`",
                    f"**Content Type:** `{content_type}`"
                ]
                
                # Add threat level if NSFW
                if is_nsfw:
                    description.append(f"**Dreigingsniveau:** `{threat_level.upper()}`")
                
                # Add scan result with proper formatting
                description.append(f"**Scan resultaat:** ```{scan_result}```")
                
                # Join all parts with newlines
                full_description = "\n".join(description)
                
                # Create the embed with all the information
                embed = discord.Embed(
                    title=title,
                    description=full_description,
                    color=color,
                    timestamp=timestamp
                )
                
                # Add user avatar as thumbnail
                embed.set_thumbnail(url=user.display_avatar.url)
                
                # Add a thumbnail of the media if it's an image and not NSFW
                if content_type == "image" and not is_nsfw:
                    # Create a field with a link to the image instead of embedding it directly
                    embed.add_field(
                        name="Media Preview",
                        value=f"[Bekijk afbeelding]({media_url})",
                        inline=False
                    )
                
                # Add file information
                try:
                    import os
                    from urllib.parse import urlparse
                    parsed_url = urlparse(media_url)
                    filename = os.path.basename(parsed_url.path)
                    
                    file_info = [
                        f"**Bestandsnaam:** `{filename}`"
                    ]
                    
                    # Try to get file extension
                    if "." in filename:
                        extension = filename.split(".")[-1].lower()
                        file_info.append(f"**Extensie:** `{extension}`")
                    
                    embed.add_field(
                        name="Bestandsinformatie",
                        value="\n".join(file_info),
                        inline=False
                    )
                except Exception as e:
                    print(f"[MEDIA SCAN LOG] Error parsing media URL: {e}")
                
                # Add server information if available
                if hasattr(user, "guild") and user.guild:
                    embed.add_field(
                        name="Server Informatie",
                        value=f"**Naam:** {user.guild.name}\n**ID:** `{user.guild.id}`",
                        inline=False
                    )
                
                # Add footer with bot name
                if is_nsfw:
                    embed.set_footer(text=f"Silcas Bot Beveiligingssysteem • Dreigingsniveau: {threat_level.upper()}")
                else:
                    embed.set_footer(text=f"Silcas Bot Beveiligingssysteem • Media geclassificeerd als VEILIG")
                
                # Send the embed to the mod channel
                await channel.send(embed=embed)
                print(f"[MEDIA SCAN LOG] Successfully sent detailed log to mod channel (ID: {MOD_LOG_CHANNEL_ID})")
            else:
                print(f"[MEDIA SCAN LOG] ⚠️ Could not find mod log channel with ID: {MOD_LOG_CHANNEL_ID}")
            
            # Log to database with enhanced information
            db.log_media_scan(
                user_id=user.id,
                username=str(user),
                ip_like=ip_like,
                media_url=media_url,
                content_type=content_type,
                is_nsfw=is_nsfw,
                scan_result=scan_result,
                threat_level=threat_level
            )
            print(f"[MEDIA SCAN LOG] Successfully logged media scan to database")
        except Exception as e:
            print(f'[MEDIA SCAN LOG] ❌ ERROR logging media scan: {e}')
            import traceback
            traceback.print_exc()
    
    async def log_violation(user, content, violation_type="Stack Buffer Overflow", scan_result=None, threat_level="medium", additional_info=None):
        """
        Enhanced logging of violations to the mod channel and database with more detailed information
        
        Parameters:
        - user: The Discord user who triggered the violation
        - content: The content that triggered the violation (message, URL, etc.)
        - violation_type: Type of violation (e.g., "Malicious URL", "NSFW Media", etc.)
        - scan_result: Results from scanning the content
        - threat_level: Severity of the threat ("low", "medium", "high", "critical")
        - additional_info: Any additional information to include in the log
        """
        try:
            # Generate an IP-like identifier for the user
            ip_like = get_user_ip_like_identifier(user.id)
            
            # Get current timestamp for consistent logging
            timestamp = datetime.datetime.now(datetime.timezone.utc)
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Set color and emoji based on threat level
            threat_colors = {
                "low": 0xFFCC00,      # Yellow
                "medium": 0xFF9900,   # Orange
                "high": 0xFF3300,     # Dark Orange
                "critical": 0xFF0000  # Red
            }
            
            threat_emojis = {
                "low": "⚠️",
                "medium": "🔶",
                "high": "🚨",
                "critical": "☣️"
            }
            
            color = threat_colors.get(threat_level, 0xFF9900)  # Default to orange if unknown
            emoji = threat_emojis.get(threat_level, "⚠️")      # Default to warning if unknown
            
            # Enhanced console logging
            print(f"[SECURITY LOG] {formatted_time} | {emoji} {threat_level.upper()} | {violation_type} | User: {user} (ID: {user.id})")
            if content and len(content) > 100:
                print(f"[SECURITY LOG] Content: {content[:100]}... (truncated)")
            else:
                print(f"[SECURITY LOG] Content: {content}")
            if scan_result:
                print(f"[SECURITY LOG] Scan Result: {scan_result}")
            if additional_info:
                print(f"[SECURITY LOG] Additional Info: {additional_info}")
            
            # Log to Discord channel
            channel = bot.get_channel(MOD_LOG_CHANNEL_ID)
            if channel:
                title = f"{emoji} {violation_type.upper()} GEDETECTEERD"
                
                # Create a more detailed and structured description
                description = [
                    f"**Gebruiker:** {user.mention}",
                    f"**Gebruikers-ID:** `{user.id}`",
                    f"**Gebruikersnaam:** `{user}`",
                    f"**IP-achtige ID:** `{ip_like}`",
                    f"**Dreigingsniveau:** `{threat_level.upper()}`",
                    f"**Tijdstip:** `{formatted_time}`"
                ]
                
                # Add content with proper formatting
                if content:
                    # If content is a URL, format it differently
                    if content.startswith(("http://", "https://", "www.")):
                        description.append(f"**URL:** `{content}`")
                    else:
                        description.append(f"**Inhoud:** ```{content}```")
                
                # Add scan result if available
                if scan_result:
                    description.append(f"**Scan resultaat:** ```{scan_result}```")
                
                # Add additional info if available
                if additional_info:
                    description.append(f"**Extra informatie:** ```{additional_info}```")
                
                # Join all parts with newlines
                full_description = "\n".join(description)
                
                # Create the embed with all the information
                embed = discord.Embed(
                    title=title,
                    description=full_description,
                    color=color,
                    timestamp=timestamp
                )
                
                # Add user avatar as thumbnail
                embed.set_thumbnail(url=user.display_avatar.url)
                
                # Add server information if available
                if hasattr(user, "guild") and user.guild:
                    embed.add_field(
                        name="Server Informatie",
                        value=f"**Naam:** {user.guild.name}\n**ID:** `{user.guild.id}`",
                        inline=False
                    )
                
                # Add footer with bot name
                embed.set_footer(text=f"Silcas Bot Beveiligingssysteem • Dreigingsniveau: {threat_level.upper()}")
                
                # Send the embed to the mod channel
                await channel.send(embed=embed)
                print(f"[SECURITY LOG] Successfully sent detailed log to mod channel (ID: {MOD_LOG_CHANNEL_ID})")
            else:
                print(f"[SECURITY LOG] ⚠️ Could not find mod log channel with ID: {MOD_LOG_CHANNEL_ID}")
            
            # Log to database with enhanced information
            db.log_violation(
                user_id=user.id,
                username=str(user),
                ip_like=ip_like,
                content=content,
                violation_type=violation_type,
                scan_result=scan_result,
                threat_level=threat_level,
                additional_info=additional_info
            )
            print(f"[SECURITY LOG] Successfully logged violation to database")
        except Exception as e:
            print(f'[SECURITY LOG] ❌ ERROR logging violation: {e}')
            import traceback
            traceback.print_exc()
    
    # Add a simple command to test if the bot is working
    @bot.command(name="ping")
    async def ping_prefix(ctx):
        print(f"[COMMAND] Ping command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        latency = round(bot.latency * 1000)
        await send_temp_message(ctx, f"Pong! Bot latency: {latency}ms")
        print(f"[COMMAND] Ping response sent with latency: {latency}ms")
        
    # Add a slash command version of ping
    @bot.tree.command(name="ping", description="Test of de bot werkt en toon de latency")
    async def ping_slash(interaction: discord.Interaction):
        print(f"[SLASH] Ping slash command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
        latency = round(bot.latency * 1000)
        # For slash commands, we use ephemeral=True instead of delete_after
        # This makes the message only visible to the user who ran the command
        await interaction.response.send_message(f"Pong! Bot latency: {latency}ms", ephemeral=True)
        print(f"[SLASH] Ping slash response sent with latency: {latency}ms (ephemeral)")
        
    # Helper function to perform a mute operation
    async def perform_mute(member, duration, reason, moderator_name, guild_id, guild_name):
        """Common function to perform a mute operation"""
        # Calculate timeout duration
        timeout_duration = datetime.timedelta(minutes=duration)
        
        # Apply the timeout
        await member.timeout(timeout_duration, reason=reason)
        
        # Log to database
        import dashboard_db as db
        timeout_until = (datetime.datetime.now(datetime.UTC) + timeout_duration).isoformat()
        db.log_timeout(
            user_id=str(member.id),
            username=str(member),
            guild_id=str(guild_id),
            guild_name=guild_name,
            timeout_until=timeout_until,
            reason=reason
        )
        
        # Create embed for response
        embed = discord.Embed(
            title="✅ Gebruiker Gemute",
            description=f"{member.mention} is gemute voor {duration} minuten.\nReden: {reason}",
            color=discord.Color.orange()
        )
        embed.set_footer(text=f"Gemute door {moderator_name}")
        embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
        
        # Log to mod channel if configured
        try:
            await log_violation(member, f"Mute door {moderator_name}", "Manual Mute", reason)
        except Exception as e:
            print(f"[MUTE] Error logging to mod channel: {e}")
            
        return embed
    
    # Add a prefix version of the mute command
    @bot.command(name="mute")
    @commands.has_permissions(moderate_members=True)
    async def mute_user_prefix(ctx, member: discord.Member = None, duration: int = 10, *, reason="Geen reden opgegeven"):
        """Mute a user for a specified duration"""
        print(f"[COMMAND] Mute command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        if member is None:
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te muten. Gebruik: `/mute @gebruiker [duur] [reden]`")
            return
            
        # Check if the bot has permission to moderate members
        if not ctx.guild.me.guild_permissions.moderate_members:
            await send_temp_message(ctx, "❌ De bot heeft geen toestemming om gebruikers te muten. Geef de bot de 'Moderate Members' permissie.")
            return
            
        # Check if the member is the server owner
        if member.id == ctx.guild.owner_id:
            await send_temp_message(ctx, f"❌ Kan {member.mention} niet muten omdat deze gebruiker de eigenaar van de server is.")
            return
            
        # Check if the member's highest role is higher than the bot's highest role
        if member.top_role >= ctx.guild.me.top_role:
            await send_temp_message(ctx, f"❌ Kan {member.mention} niet muten. Deze gebruiker heeft een hogere of gelijke rol dan de bot.")
            return
            
        # Send initial response
        initial_msg = await ctx.send(f"⏳ Bezig met muten van {member.mention} voor {duration} minuten...")
        
        try:
            # Perform the mute
            embed = await perform_mute(
                member=member, 
                duration=duration, 
                reason=reason, 
                moderator_name=ctx.author, 
                guild_id=ctx.guild.id, 
                guild_name=ctx.guild.name
            )
            
            # Send confirmation message
            await ctx.send(embed=embed)
            
        except Exception as e:
            print(f"[MUTE] Error in mute command: {e}")
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(e)}")
    
    # Error handler for the mute command
    @mute_user_prefix.error
    async def mute_error(ctx, error):
        if isinstance(error, commands.MissingPermissions):
            print(f"[ERROR] Command error in mute from {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'} channel")
            print(f"[ERROR] User lacks required permissions: {error.missing_permissions}")
            
            # Create a more user-friendly error message
            await send_temp_message(ctx, "❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Je hebt de 'Leden Modereren' (Moderate Members) permissie nodig om gebruikers te muten of een timeout te geven.")
        elif isinstance(error, commands.MissingRequiredArgument):
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te muten. Gebruik: `/mute @gebruiker [duur] [reden]`")
        elif isinstance(error, commands.BadArgument):
            await send_temp_message(ctx, "❌ Kon de opgegeven gebruiker niet vinden of ongeldige duur opgegeven. Zorg ervoor dat je een geldige gebruiker vermeldt.")
        else:
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(error)}")
            print(f"[MUTE ERROR] Unhandled error in mute command: {error}")
    
    # Add a slash command version of mute
    @bot.tree.command(name="mute", description="Tijdelijk een gebruiker muten in de server")
    @discord.app_commands.describe(
        member="De gebruiker die je wilt muten",
        duration="Duur van de mute in minuten (standaard: 10)",
        reason="De reden voor de mute"
    )
    async def mute_user_slash(interaction: discord.Interaction, member: discord.Member, duration: int = 10, reason: str = "Geen reden opgegeven"):
        """Mute a user for a specified duration"""
        try:
            print(f"[SLASH] Mute command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
            
            # Check if user has moderate_members permission
            if not interaction.user.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om gebruikers te muten. Je hebt de 'Moderate Members' permissie nodig.", ephemeral=True)
                return
                
            # Check if the bot has permission to moderate members
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ De bot heeft geen toestemming om gebruikers te muten. Geef de bot de 'Moderate Members' permissie.", ephemeral=True)
                return
                
            # Check if the member is the server owner
            if member.id == interaction.guild.owner_id:
                await interaction.response.send_message(f"❌ Kan {member.mention} niet muten omdat deze gebruiker de eigenaar van de server is.", ephemeral=True)
                return
                
            # Check if the member's highest role is higher than the bot's highest role
            if member.top_role >= interaction.guild.me.top_role:
                await interaction.response.send_message(f"❌ Kan {member.mention} niet muten. Deze gebruiker heeft een hogere of gelijke rol dan de bot.", ephemeral=True)
                return
                
            # Send initial response
            await interaction.response.send_message(f"⏳ Bezig met muten van {member.mention} voor {duration} minuten...", ephemeral=False)
            
            # Perform the mute
            embed = await perform_mute(
                member=member, 
                duration=duration, 
                reason=reason, 
                moderator_name=interaction.user, 
                guild_id=interaction.guild.id, 
                guild_name=interaction.guild.name
            )
            
            # Send confirmation message
            await interaction.followup.send(embed=embed)
                
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for mute command: {e}")
            print(f"Error in mute slash command: {e}")
    
    # Helper function to perform an unban operation
    async def perform_unban(ctx, user_id, reason="Unbanned via command"):
        """Common function to perform an unban operation"""
        try:
            # Try to convert the user_id to an integer
            try:
                user_id = int(user_id)
            except ValueError:
                # If it's not a valid integer, it might be a user mention or name
                if ctx.message and hasattr(ctx, 'message'):
                    # For prefix commands
                    if len(ctx.message.mentions) > 0:
                        user_id = ctx.message.mentions[0].id
                    else:
                        # Try to find the user by name
                        return await ctx.send("❌ Ongeldige gebruiker ID. Geef een geldig gebruiker ID op.")
                else:
                    # For slash commands
                    return await ctx.send("❌ Ongeldige gebruiker ID. Geef een geldig gebruiker ID op.")
            
            # Create a User object from the ID
            user = await bot.fetch_user(user_id)
            
            if not user:
                return await ctx.send(f"❌ Kon geen gebruiker vinden met ID: {user_id}")
                
            # Check if the user is banned
            try:
                ban_entry = await ctx.guild.fetch_ban(user)
                print(f"[UNBAN] User {user} is banned, attempting to unban")
            except discord.NotFound:
                print(f"[UNBAN] User {user} is not banned")
                return await ctx.send(f"❌ {user} is niet verbannen van deze server.")
                
            # Unban the user
            await ctx.guild.unban(user, reason=reason)
            print(f"[UNBAN] Successfully unbanned {user}")
            
            # Log to database
            import dashboard_db as db
            db.remove_ban(str(user.id), str(ctx.guild.id))
            
            # Create embed for response
            embed = discord.Embed(
                title="✅ Gebruiker Unbanned",
                description=f"{user.mention} is succesvol unbanned.\nReden: {reason}",
                color=discord.Color.green()
            )
            embed.set_footer(text=f"Unbanned door {ctx.author}")
            embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
            
            return embed
            
        except discord.Forbidden:
            print(f"[UNBAN ERROR] Bot lacks permission to unban users")
            await ctx.send("❌ De bot heeft geen toestemming om gebruikers te unbannen. Geef de bot de 'Ban Members' permissie.")
            return None
        except discord.HTTPException as e:
            print(f"[UNBAN ERROR] HTTP Exception: {e}")
            await ctx.send(f"❌ Er is een fout opgetreden bij het unbannen: {e}")
            return None
        except Exception as e:
            print(f"[UNBAN ERROR] Unexpected error: {e}")
            await ctx.send(f"❌ Er is een onverwachte fout opgetreden: {e}")
            return None
    
    # Add a prefix version of the unban command
    @bot.command(name="unban")
    @commands.has_permissions(ban_members=True)
    async def unban_user_prefix(ctx, user_id: str = None, *, reason="Geen reden opgegeven"):
        """Unban a user from the server"""
        print(f"[COMMAND] Unban command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        if user_id is None:
            await send_temp_message(ctx, "❌ Je moet een gebruiker ID opgeven om te unbannen. Gebruik: `/unban [user_id] [reden]`")
            return
            
        # Check if the bot has permission to ban members
        if not ctx.guild.me.guild_permissions.ban_members:
            await send_temp_message(ctx, "❌ De bot heeft geen toestemming om gebruikers te unbannen. Geef de bot de 'Ban Members' permissie.")
            return
            
        # Send initial response
        initial_msg = await ctx.send(f"⏳ Bezig met unbannen van gebruiker ID {user_id}...")
        
        try:
            # Create a context wrapper for slash commands
            class PrefixContext:
                def __init__(self, ctx):
                    self.author = ctx.author
                    self.guild = ctx.guild
                    self.message = ctx.message
                    self.send = ctx.send
                    
            ctx_wrapper = PrefixContext(ctx)
            
            # Perform the unban
            embed = await perform_unban(ctx_wrapper, user_id, reason)
            
            if embed:
                # Send confirmation message
                await ctx.send(embed=embed)
            
        except Exception as e:
            print(f"[UNBAN] Error in unban command: {e}")
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(e)}")
    
    # Error handler for the unban command
    @unban_user_prefix.error
    async def unban_error(ctx, error):
        print(f"[ERROR] Command error in unban from {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'} channel")
        if isinstance(error, commands.MissingPermissions):
            print(f"[ERROR] User lacks required permissions: {error.missing_permissions}")
            
            # Create a more user-friendly error message
            await send_temp_message(ctx, "❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Je hebt de 'Leden Verbannen' (Ban Members) permissie nodig om gebruikers te unbannen.")
        elif isinstance(error, commands.MissingRequiredArgument):
            print(f"[ERROR] Missing required argument: {error.param.name}")
            await send_temp_message(ctx, "❌ Je moet een gebruiker ID opgeven om te unbannen. Gebruik: `/unban [user_id] [reden]`")
        elif isinstance(error, commands.BadArgument):
            print(f"[ERROR] Bad argument: {error}")
            await send_temp_message(ctx, "❌ Ongeldige gebruiker ID. Geef een geldig gebruiker ID op.")
        else:
            print(f"[ERROR] Unhandled error in unban command: {error}")
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(error)}")
    
    # Add a slash command version of unban
    @bot.tree.command(name="unban", description="Verwijder een ban van een gebruiker")
    @discord.app_commands.describe(
        user_id="De ID van de gebruiker die je wilt unbannen",
        reason="De reden voor het unbannen"
    )
    async def unban_user_slash(interaction: discord.Interaction, user_id: str, reason: str = "Geen reden opgegeven"):
        """Unban a user from the server"""
        try:
            print(f"[SLASH] Unban command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
            
            # Check if user has ban_members permission
            if not interaction.user.guild_permissions.ban_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om gebruikers te unbannen. Je hebt de 'Ban Members' permissie nodig.", ephemeral=True)
                return
                
            # Check if the bot has permission to ban members
            if not interaction.guild.me.guild_permissions.ban_members:
                await interaction.response.send_message("❌ De bot heeft geen toestemming om gebruikers te unbannen. Geef de bot de 'Ban Members' permissie.", ephemeral=True)
                return
                
            # Send initial response
            await interaction.response.send_message(f"⏳ Bezig met unbannen van gebruiker ID {user_id}...", ephemeral=False)
            
            # Create a context wrapper for slash commands
            class SlashContext:
                def __init__(self, interaction):
                    self.author = interaction.user
                    self.guild = interaction.guild
                    self.message = None
                    self.responded = False
                    self.interaction = interaction
                    
                async def send(self, content=None, embed=None):
                    if not self.responded:
                        await self.interaction.followup.send(content=content, embed=embed)
                        self.responded = True
                    else:
                        await self.interaction.followup.send(content=content, embed=embed)
            
            ctx = SlashContext(interaction)
            
            # Perform the unban
            embed = await perform_unban(ctx, user_id, reason)
            
            if embed:
                # Send confirmation message
                await interaction.followup.send(embed=embed)
                
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for unban command: {e}")
            print(f"Error in unban slash command: {e}")
    
    # Add a timeout command (alias for mute)
    @bot.command(name="timeout")
    @commands.has_permissions(moderate_members=True)
    async def timeout_user_prefix(ctx, member: discord.Member = None, duration: int = 10, *, reason="Geen reden opgegeven"):
        """Timeout a user for a specified duration (alias for mute)"""
        print(f"[COMMAND] Timeout command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        # Call the mute command implementation
        await mute_user_prefix(ctx, member, duration, reason=reason)
    
    # Error handler for the timeout command
    @timeout_user_prefix.error
    async def timeout_error(ctx, error):
        # Call the mute error handler
        await mute_error(ctx, error)
    
    # Add a slash command version of timeout
    @bot.tree.command(name="timeout", description="Tijdelijk een gebruiker een timeout geven in de server")
    @discord.app_commands.describe(
        member="De gebruiker die je een timeout wilt geven",
        duration="Duur van de timeout in minuten (standaard: 10)",
        reason="De reden voor de timeout"
    )
    async def timeout_user_slash(interaction: discord.Interaction, member: discord.Member, duration: int = 10, reason: str = "Geen reden opgegeven"):
        """Timeout a user for a specified duration (alias for mute)"""
        try:
            print(f"[SLASH] Timeout command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
            
            # Check if user has moderate_members permission
            if not interaction.user.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om gebruikers een timeout te geven. Je hebt de 'Moderate Members' permissie nodig.", ephemeral=True)
                return
                
            # Check if the bot has permission to moderate members
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ De bot heeft geen toestemming om gebruikers een timeout te geven. Geef de bot de 'Moderate Members' permissie.", ephemeral=True)
                return
                
            # Check if the member is the server owner
            if member.id == interaction.guild.owner_id:
                await interaction.response.send_message(f"❌ Kan {member.mention} geen timeout geven omdat deze gebruiker de eigenaar van de server is.", ephemeral=True)
                return
                
            # Check if the member's highest role is higher than the bot's highest role
            if member.top_role >= interaction.guild.me.top_role:
                await interaction.response.send_message(f"❌ Kan {member.mention} geen timeout geven. Deze gebruiker heeft een hogere of gelijke rol dan de bot.", ephemeral=True)
                return
                
            # Send initial response
            await interaction.response.send_message(f"⏳ Bezig met timeout geven aan {member.mention} voor {duration} minuten...", ephemeral=False)
            
            # Perform the timeout (same as mute)
            embed = await perform_mute(
                member=member, 
                duration=duration, 
                reason=reason, 
                moderator_name=interaction.user, 
                guild_id=interaction.guild.id, 
                guild_name=interaction.guild.name
            )
            
            # Customize the embed for timeout
            embed.title = "✅ Gebruiker Timeout"
            embed.description = f"{member.mention} heeft een timeout gekregen voor {duration} minuten.\nReden: {reason}"
            embed.set_footer(text=f"Timeout door {interaction.user}")
            
            # Send confirmation message
            await interaction.followup.send(embed=embed)
                
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for timeout command: {e}")
            print(f"Error in timeout slash command: {e}")
    
    # Helper function to perform an unmute operation
    async def perform_unmute(member, moderator_name, guild_id, guild_name, reason="Timeout removed via command"):
        """Common function to perform an unmute operation"""
        # Check if the user is actually timed out
        is_timed_out = False
        if hasattr(member, 'communication_disabled_until') and member.communication_disabled_until is not None:
            is_timed_out = True
        
        # Remove the timeout
        await member.timeout(None, reason=reason)
        
        # Get user's active timeouts from database
        import dashboard_db as db
        timeouts = db.get_active_timeouts()
        user_timeouts = [timeout for timeout in timeouts if timeout['user_id'] == str(member.id) and timeout['guild_id'] == str(guild_id)]
        
        # Remove from database if found
        if user_timeouts:
            for timeout in user_timeouts:
                db.remove_timeout(timeout['id'])
                
        # Create embed for response
        if is_timed_out:
            embed = discord.Embed(
                title="✅ Gebruiker Unmuted",
                description=f"{member.mention} is succesvol unmuted.",
                color=discord.Color.green()
            )
        else:
            embed = discord.Embed(
                title="ℹ️ Gebruiker Unmuted",
                description=f"{member.mention} was niet gemute, maar eventuele database records zijn verwijderd.",
                color=discord.Color.blue()
            )
            
        embed.set_footer(text=f"Unmuted door {moderator_name}")
        embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
        
        return embed
    
    # Add a prefix version of the unmute command
    @bot.command(name="unmute")
    @commands.has_permissions(moderate_members=True)
    async def unmute_user_prefix(ctx, member: discord.Member = None):
        """Remove a timeout from a user"""
        print(f"[COMMAND] Unmute command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        if member is None:
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te unmuten. Gebruik: `/unmute @gebruiker`")
            return
            
        # Check if the bot has permission to moderate members
        if not ctx.guild.me.guild_permissions.moderate_members:
            await send_temp_message(ctx, "❌ De bot heeft geen toestemming om gebruikers te unmuten. Geef de bot de 'Moderate Members' permissie.")
            return
            
        # Send initial response
        initial_msg = await ctx.send(f"⏳ Bezig met unmuten van {member.mention}...")
        
        try:
            # Perform the unmute
            embed = await perform_unmute(
                member=member, 
                moderator_name=ctx.author, 
                guild_id=ctx.guild.id, 
                guild_name=ctx.guild.name
            )
            
            # Send confirmation message
            await ctx.send(embed=embed)
            
        except Exception as e:
            print(f"[UNMUTE] Error in unmute command: {e}")
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(e)}")
    
    # Error handler for the unmute command
    @unmute_user_prefix.error
    async def unmute_error(ctx, error):
        if isinstance(error, commands.MissingPermissions):
            print(f"[ERROR] Command error in unmute from {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'} channel")
            print(f"[ERROR] User lacks required permissions: {error.missing_permissions}")
            
            # Create a more user-friendly error message
            await send_temp_message(ctx, "❌ Je hebt niet de juiste permissies om dit commando te gebruiken. Je hebt de 'Leden Modereren' (Moderate Members) permissie nodig om gebruikers te unmuten of een timeout te verwijderen.")
        elif isinstance(error, commands.MissingRequiredArgument):
            await send_temp_message(ctx, "❌ Je moet een gebruiker opgeven om te unmuten. Gebruik: `/unmute @gebruiker`")
        elif isinstance(error, commands.BadArgument):
            await send_temp_message(ctx, "❌ Kon de opgegeven gebruiker niet vinden. Zorg ervoor dat je een geldige gebruiker vermeldt.")
        else:
            await send_temp_message(ctx, f"❌ Er is een fout opgetreden: {str(error)}")
            print(f"[UNMUTE ERROR] Unhandled error in unmute command: {error}")
    
    # Add a slash command version of unmute
    @bot.tree.command(name="unmute", description="Verwijder een mute van een gebruiker")
    @discord.app_commands.describe(
        member="De gebruiker die je wilt unmuten"
    )
    async def unmute_user_slash(interaction: discord.Interaction, member: discord.Member):
        """Remove a timeout from a user"""
        try:
            print(f"[SLASH] Unmute command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
            
            # Check if user has moderate_members permission
            if not interaction.user.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om gebruikers te unmuten. Je hebt de 'Moderate Members' permissie nodig.", ephemeral=True)
                return
                
            # Check if the bot has permission to moderate members
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ De bot heeft geen toestemming om gebruikers te unmuten. Geef de bot de 'Moderate Members' permissie.", ephemeral=True)
                return
                
            # Send initial response
            await interaction.response.send_message(f"⏳ Bezig met unmuten van {member.mention}...", ephemeral=False)
            
            # Perform the unmute
            embed = await perform_unmute(
                member=member, 
                moderator_name=interaction.user, 
                guild_id=interaction.guild.id, 
                guild_name=interaction.guild.name
            )
            
            # Send confirmation message
            await interaction.followup.send(embed=embed)
                
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for unmute command: {e}")
            print(f"Error in unmute slash command: {e}")
            
    # Add untimeout command (alias for unmute)
    @bot.command(name="untimeout")
    @commands.has_permissions(moderate_members=True)
    async def untimeout_user_prefix(ctx, member: discord.Member = None):
        """Remove a timeout from a user (alias for unmute)"""
        print(f"[COMMAND] Untimeout command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        
        # Call the unmute command implementation
        await unmute_user_prefix(ctx, member)
    
    # Error handler for the untimeout command
    @untimeout_user_prefix.error
    async def untimeout_error(ctx, error):
        # Call the unmute error handler
        await unmute_error(ctx, error)
    
    # Add a slash command version of untimeout
    @bot.tree.command(name="untimeout", description="Verwijder een timeout van een gebruiker")
    @discord.app_commands.describe(
        member="De gebruiker waarvan je de timeout wilt verwijderen"
    )
    async def untimeout_user_slash(interaction: discord.Interaction, member: discord.Member):
        """Remove a timeout from a user (alias for unmute)"""
        try:
            print(f"[SLASH] Untimeout command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
            
            # Check if user has moderate_members permission
            if not interaction.user.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ Je hebt geen toestemming om timeouts te verwijderen. Je hebt de 'Moderate Members' permissie nodig.", ephemeral=True)
                return
                
            # Check if the bot has permission to moderate members
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("❌ De bot heeft geen toestemming om timeouts te verwijderen. Geef de bot de 'Moderate Members' permissie.", ephemeral=True)
                return
                
            # Send initial response
            await interaction.response.send_message(f"⏳ Bezig met verwijderen van timeout voor {member.mention}...", ephemeral=False)
            
            # Perform the unmute
            embed = await perform_unmute(
                member=member, 
                moderator_name=interaction.user, 
                guild_id=interaction.guild.id, 
                guild_name=interaction.guild.name,
                reason="Timeout removed via untimeout command"
            )
            
            # Customize the embed for untimeout
            embed.title = "✅ Timeout Verwijderd"
            embed.description = f"Timeout voor {member.mention} is succesvol verwijderd."
            embed.set_footer(text=f"Timeout verwijderd door {interaction.user}")
            
            # Send confirmation message
            await interaction.followup.send(embed=embed)
                
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for untimeout command: {e}")
            print(f"Error in untimeout slash command: {e}")
    
    # Add a command to force sync slash commands - no permissions required for testing
    @bot.command(name="sync")
    async def sync_commands_prefix(ctx, guild_only: bool = True):
        """Force sync slash commands with Discord"""
        print(f"[COMMAND] Sync command executed by {ctx.author} in {ctx.guild.name if ctx.guild else 'DM'}")
        sync_msg = await ctx.send("⏳ Synchroniseren van slash commands... Dit kan enkele seconden duren.")
        print(f"[SYNC] Starting sync process...")
        
        try:
            # List all commands that will be synced
            commands_list = bot.tree.get_commands()
            command_names = [f"/{cmd.name}" for cmd in commands_list]
            print(f"[SYNC] Commands to sync: {', '.join(command_names)}")
            
            if guild_only and ctx.guild:
                # Sync only to the current guild
                print(f"[SYNC] Syncing commands to guild: {ctx.guild.name} (ID: {ctx.guild.id})...")
                await bot.tree.sync(guild=ctx.guild)
                print(f"[SYNC] Guild sync complete for {ctx.guild.name}")
            else:
                # Clear existing commands first
                print(f"[SYNC] Clearing existing commands...")
                bot.tree.clear_commands(guild=None)
                
                # Sync globally
                print(f"[SYNC] Syncing commands globally...")
                await bot.tree.sync()
                print(f"[SYNC] Global sync complete")
                
                # Sync to the current guild specifically
                if ctx.guild:
                    print(f"[SYNC] Syncing commands to guild: {ctx.guild.name} (ID: {ctx.guild.id})...")
                    await bot.tree.sync(guild=ctx.guild)
                    print(f"[SYNC] Guild sync complete for {ctx.guild.name}")
            
            # Try to delete the initial message
            try:
                await sync_msg.delete()
                print(f"[SYNC] Deleted initial sync message")
            except Exception as delete_error:
                print(f"[SYNC] Could not delete initial message: {delete_error}")
                pass
            
            # Create a detailed success message
            success_message = "✅ Slash commands zijn gesynchroniseerd!\n\n"
            success_message += f"**Geregistreerde commands ({len(command_names)}):**\n"
            success_message += ", ".join(command_names) + "\n\n"
            success_message += "**Belangrijk:**\n"
            success_message += "- Globale commands kunnen tot een uur duren om zichtbaar te worden\n"
            success_message += "- Guild-specifieke commands zouden direct zichtbaar moeten zijn\n"
            success_message += "- Als commands nog steeds niet zichtbaar zijn, controleer of de bot de 'applications.commands' scope heeft\n"
            success_message += "- Bij 'rate limit' fouten, gebruik het /sync commando met de optie 'guild_only=True'"
                
            # Send success message that will auto-delete after 30 seconds (longer because it's more detailed)
            await ctx.send(success_message, delete_after=30)
            print(f"[SYNC] Sync process completed successfully")
        except Exception as e:
            print(f"[SYNC ERROR] Failed to sync commands: {e}")
            
            # Try to delete the initial message
            try:
                await sync_msg.delete()
                print(f"[SYNC] Deleted initial sync message after error")
            except:
                print(f"[SYNC] Could not delete initial message after error")
                pass
                
            # Send a more detailed error message
            error_message = f"❌ Fout bij synchroniseren van commands: {e}\n\n"
            error_message += "**Mogelijke oplossingen:**\n"
            error_message += "1. Controleer of de bot de juiste scopes heeft (bot EN applications.commands)\n"
            error_message += "2. Probeer de bot opnieuw uit te nodigen met de juiste scopes\n"
            error_message += "3. Het kan tot een uur duren voordat globale commands zichtbaar worden"
            
            await ctx.send(error_message, delete_after=30)
            print(f"[SYNC] Sent error message to user")
            
    # Add slash command version of sync - no permissions required for testing
    @bot.tree.command(name="sync", description="Synchroniseer slash commands met Discord")
    @discord.app_commands.describe(
        guild_only="Alleen synchroniseren met de huidige server (voorkomt rate limits)"
    )
    async def sync_commands_slash(interaction: discord.Interaction, guild_only: bool = True):
        """Force sync slash commands with Discord"""
        print(f"[SLASH] Sync slash command executed by {interaction.user} in {interaction.guild.name if interaction.guild else 'DM'}")
        # Use ephemeral=True to make the initial message only visible to the user
        await interaction.response.send_message("⏳ Synchroniseren van slash commands... Dit kan enkele seconden duren.", ephemeral=True)
        print(f"[SLASH SYNC] Starting sync process...")
        
        try:
            # List all commands that will be synced
            commands_list = bot.tree.get_commands()
            command_names = [f"/{cmd.name}" for cmd in commands_list]
            print(f"[SLASH SYNC] Commands to sync: {', '.join(command_names)}")
            
            if guild_only and interaction.guild:
                # Sync only to the current guild
                print(f"[SLASH SYNC] Syncing commands to guild: {interaction.guild.name} (ID: {interaction.guild.id})...")
                await bot.tree.sync(guild=interaction.guild)
                print(f"[SLASH SYNC] Guild sync complete for {interaction.guild.name}")
            else:
                # Clear existing commands first
                print(f"[SLASH SYNC] Clearing existing commands...")
                bot.tree.clear_commands(guild=None)
                
                # Sync globally
                print(f"[SLASH SYNC] Syncing commands globally...")
                await bot.tree.sync()
                print(f"[SLASH SYNC] Global sync complete")
                
                # Sync to the current guild specifically
                if interaction.guild:
                    print(f"[SLASH SYNC] Syncing commands to guild: {interaction.guild.name} (ID: {interaction.guild.id})...")
                    await bot.tree.sync(guild=interaction.guild)
                    print(f"[SLASH SYNC] Guild sync complete for {interaction.guild.name}")
            
            # Create a detailed success message
            success_message = "✅ Slash commands zijn gesynchroniseerd!\n\n"
            success_message += f"**Geregistreerde commands ({len(command_names)}):**\n"
            success_message += ", ".join(command_names) + "\n\n"
            
            if guild_only and interaction.guild:
                success_message += f"**Synchronisatie type:** Alleen voor server '{interaction.guild.name}'\n\n"
            else:
                success_message += "**Synchronisatie type:** Globaal (alle servers)\n\n"
                
            success_message += "**Belangrijk:**\n"
            
            if not guild_only:
                success_message += "- Globale commands kunnen tot een uur duren om zichtbaar te worden\n"
            else:
                success_message += "- Guild-specifieke commands zouden direct zichtbaar moeten zijn\n"
                
            success_message += "- Als commands nog steeds niet zichtbaar zijn, controleer of de bot de 'applications.commands' scope heeft\n"
            success_message += "- Bij 'rate limit' fouten, gebruik de optie 'guild_only=True' om alleen met de huidige server te synchroniseren"
                
            # Send success message, also ephemeral
            await interaction.followup.send(success_message, ephemeral=True)
            print(f"[SLASH SYNC] Sync process completed successfully")
        except Exception as e:
            print(f"[SLASH SYNC ERROR] Failed to sync commands: {e}")
            
            # Send a more detailed error message
            error_message = f"❌ Fout bij synchroniseren van commands: {e}\n\n"
            error_message += "**Mogelijke oplossingen:**\n"
            error_message += "1. Controleer of de bot de juiste scopes heeft (bot EN applications.commands)\n"
            error_message += "2. Probeer de bot opnieuw uit te nodigen met de juiste scopes\n"
            error_message += "3. Het kan tot een uur duren voordat globale commands zichtbaar worden"
            
            # Send error message, also ephemeral
            await interaction.followup.send(error_message, ephemeral=True)
            print(f"[SLASH SYNC] Sent error message to user")
    
    # Add a command to scan URLs
    # Keep the original prefix command for backward compatibility
    @bot.command(name="scanlink")
    async def scan_link_prefix(ctx, url=None):
        if not url:
            await send_temp_message(ctx, "Gebruik: !scanlink <url>")
            return
        
        # Check if the provided text is a valid URL
        if not re.match(URL_PATTERN, url):
            await send_temp_message(ctx, "Ongeldige URL. Zorg ervoor dat je een geldige URL invoert beginnend met http:// of https://")
            return
        
        # Send a message indicating that the scan is in progress
        message = await ctx.send(f"🔍 URL wordt gescand, even geduld...")
        
        # Scan the URL
        is_malicious, scan_result, threat_level = await scan_url(url)
        
        # Log the URL scan with threat level
        print(f"[SCANLINK] Logging URL scan to database with threat level: {threat_level}")
        await log_url_scan(ctx.author, url, is_malicious, scan_result, threat_level)
        
        # Check if Safe Display Mode is enabled
        import dashboard_db as db
        safe_display_mode = db.is_safe_display_mode_enabled()
        
        # Update the message with the scan results
        if is_malicious:
            # Set colors and icons based on threat level
            threat_colors = {
                "low": discord.Color.gold(),      # Yellow
                "medium": discord.Color.orange(),  # Orange
                "high": 0xFF3300,                 # Dark Orange
                "critical": discord.Color.red()    # Red
            }
            
            threat_icons = {
                "low": "⚠️",
                "medium": "⚠️",
                "high": "🚨",
                "critical": "☣️"
            }
            
            threat_descriptions = {
                "low": "mogelijk verdacht",
                "medium": "verdacht",
                "high": "gevaarlijk",
                "critical": "zeer gevaarlijk"
            }
            
            color = threat_colors.get(threat_level, discord.Color.red())
            icon = threat_icons.get(threat_level, "⚠️")
            description = threat_descriptions.get(threat_level, "verdacht")
            
            embed = discord.Embed(
                title=f"{icon} {description.upper()} LINK GEDETECTEERD",
                description=f"Er is een {description} URL gescand!",
                color=color
            )
            
            # Add a thumbnail based on threat type
            if "IP Logger" in scan_result:
                embed.set_thumbnail(url="https://i.imgur.com/JWxMJmV.png")  # IP tracking icon
            elif "Malware" in scan_result:
                embed.set_thumbnail(url="https://i.imgur.com/GnyVSAd.png")  # Virus icon
            elif "Phishing" in scan_result:
                embed.set_thumbnail(url="https://i.imgur.com/QKpyYiY.png")  # Phishing icon
            elif "NSFW" in scan_result:
                embed.set_thumbnail(url="https://i.imgur.com/JzOSQXk.png")  # NSFW icon
            elif "Cryptocurrency" in scan_result:
                embed.set_thumbnail(url="https://i.imgur.com/8bYkxXt.png")  # Crypto scam icon
            else:
                embed.set_thumbnail(url="https://i.imgur.com/YkqVKfM.png")  # General warning icon
            
            # Add detection details with formatting
            embed.add_field(name="🔍 Detectie Details", value=f"```{scan_result}```", inline=False)
            
            # Add information about the threat with more details
            threat_info = ""
            if "IP Logger" in scan_result:
                threat_info += "• **IP Logger**: Deze link kan je IP-adres en locatie stelen.\n"
            if "Malware" in scan_result:
                threat_info += "• **Malware**: Deze link kan schadelijke software bevatten.\n"
            if "Phishing" in scan_result:
                threat_info += "• **Phishing**: Deze link probeert mogelijk je inloggegevens te stelen.\n"
            if "NSFW" in scan_result:
                threat_info += "• **NSFW Content**: Deze link bevat mogelijk ongepaste inhoud.\n"
            if "Obfuscated" in scan_result:
                threat_info += "• **Verborgen Link**: Deze link gebruikt technieken om zijn ware doel te verbergen.\n"
            if "Cryptocurrency" in scan_result:
                threat_info += "• **Crypto Scam**: Deze link is mogelijk een cryptocurrency-oplichting.\n"
            if "Suspicious" in scan_result:
                threat_info += "• **Verdachte Link**: Deze link vertoont verdacht gedrag.\n"
            
            if not threat_info:
                threat_info = "Deze link is als gevaarlijk gemarkeerd door ons beveiligingssysteem."
                
            embed.add_field(
                name="⚠️ Waarschuwing", 
                value=threat_info,
                inline=False
            )
            
            # Add safety tips
            embed.add_field(
                name="🛡️ Veiligheidstips", 
                value="• Klik nooit op verdachte links\n"
                      "• Deel geen persoonlijke informatie\n"
                      "• Gebruik een wachtwoordmanager\n"
                      "• Houd je software up-to-date",
                inline=False
            )
            
            # Add timestamp
            embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
            
            # In Safe Display Mode, don't show the URL directly
            if safe_display_mode:
                # Create a button view
                view = discord.ui.View()
                view.add_item(discord.ui.Button(
                    label="Toon URL (op eigen risico)", 
                    style=discord.ButtonStyle.danger,
                    url=url
                ))
                await message.edit(content=None, embed=embed, view=view)
            else:
                # Show the URL in the description
                embed.description = f"De URL `{url}` is gedetecteerd als {description}!"
                await message.edit(content=None, embed=embed)
        else:
            embed = discord.Embed(
                title="✅ URL SCAN RESULTAAT: VEILIG",
                description=f"De URL lijkt veilig te zijn.",
                color=discord.Color.green()
            )
            
            # Add a thumbnail for safe URL
            embed.set_thumbnail(url="https://i.imgur.com/5vMSsAg.png")  # Safe/shield icon
            
            # Add scan details
            embed.add_field(name="🔍 Scan Details", value=f"```{scan_result}```", inline=False)
            
            # Add safety reminder
            embed.add_field(
                name="🛡️ Veiligheidsherinnering", 
                value="Hoewel deze URL als veilig is gemarkeerd, wees altijd voorzichtig met links van onbekende bronnen.",
                inline=False
            )
            
            # Add timestamp
            embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
            
            # In Safe Display Mode, don't show the URL directly
            if safe_display_mode:
                # Create a button view
                view = discord.ui.View()
                view.add_item(discord.ui.Button(
                    label="Toon URL", 
                    style=discord.ButtonStyle.primary,
                    url=url
                ))
                await message.edit(content=None, embed=embed, view=view)
            else:
                # Show the URL in the description
                embed.description = f"De URL `{url}` lijkt veilig te zijn."
                await message.edit(content=None, embed=embed)
            
    # Add the slash command version
    @bot.tree.command(name="scanlink", description="Scan een URL op mogelijke gevaren")
    @discord.app_commands.describe(
        url="De URL die je wilt scannen"
    )
    async def scan_link_slash(interaction: discord.Interaction, url: str):
        """Scan a URL for potential threats"""
        try:
            # Check if the provided text is a valid URL
            if not re.match(URL_PATTERN, url):
                await interaction.response.send_message("Ongeldige URL. Zorg ervoor dat je een geldige URL invoert beginnend met http:// of https://", ephemeral=True)
                return
            
            # Send a message indicating that the scan is in progress
            await interaction.response.send_message(f"🔍 URL wordt gescand, even geduld...")
            
            # Scan the URL
            is_malicious, scan_result, threat_level = await scan_url(url)
            
            # Log the URL scan with threat level
            print(f"[SCANLINK SLASH] Logging URL scan to database with threat level: {threat_level}")
            await log_url_scan(interaction.user, url, is_malicious, scan_result, threat_level)
            
            # Check if Safe Display Mode is enabled
            import dashboard_db as db
            safe_display_mode = db.is_safe_display_mode_enabled()
            
            # Update the message with the scan results
            if is_malicious:
                # Set colors and icons based on threat level
                threat_colors = {
                    "low": discord.Color.gold(),      # Yellow
                    "medium": discord.Color.orange(),  # Orange
                    "high": 0xFF3300,                 # Dark Orange
                    "critical": discord.Color.red()    # Red
                }
                
                threat_icons = {
                    "low": "⚠️",
                    "medium": "⚠️",
                    "high": "🚨",
                    "critical": "☣️"
                }
                
                threat_descriptions = {
                    "low": "mogelijk verdacht",
                    "medium": "verdacht",
                    "high": "gevaarlijk",
                    "critical": "zeer gevaarlijk"
                }
                
                color = threat_colors.get(threat_level, discord.Color.red())
                icon = threat_icons.get(threat_level, "⚠️")
                description = threat_descriptions.get(threat_level, "verdacht")
                
                embed = discord.Embed(
                    title=f"{icon} {description.upper()} LINK GEDETECTEERD",
                    description=f"Er is een {description} URL gescand!",
                    color=color
                )
                
                # Add a thumbnail based on threat type
                if "IP Logger" in scan_result:
                    embed.set_thumbnail(url="https://i.imgur.com/JWxMJmV.png")  # IP tracking icon
                elif "Malware" in scan_result:
                    embed.set_thumbnail(url="https://i.imgur.com/GnyVSAd.png")  # Virus icon
                elif "Phishing" in scan_result:
                    embed.set_thumbnail(url="https://i.imgur.com/QKpyYiY.png")  # Phishing icon
                elif "NSFW" in scan_result:
                    embed.set_thumbnail(url="https://i.imgur.com/JzOSQXk.png")  # NSFW icon
                elif "Cryptocurrency" in scan_result:
                    embed.set_thumbnail(url="https://i.imgur.com/8bYkxXt.png")  # Crypto scam icon
                else:
                    embed.set_thumbnail(url="https://i.imgur.com/YkqVKfM.png")  # General warning icon
                
                # Add detection details with formatting
                embed.add_field(name="🔍 Detectie Details", value=f"```{scan_result}```", inline=False)
                
                # Add information about the threat with more details
                threat_info = ""
                if "IP Logger" in scan_result:
                    threat_info += "• **IP Logger**: Deze link kan je IP-adres en locatie stelen.\n"
                if "Malware" in scan_result:
                    threat_info += "• **Malware**: Deze link kan schadelijke software bevatten.\n"
                if "Phishing" in scan_result:
                    threat_info += "• **Phishing**: Deze link probeert mogelijk je inloggegevens te stelen.\n"
                if "NSFW" in scan_result:
                    threat_info += "• **NSFW Content**: Deze link bevat mogelijk ongepaste inhoud.\n"
                if "Obfuscated" in scan_result:
                    threat_info += "• **Verborgen Link**: Deze link gebruikt technieken om zijn ware doel te verbergen.\n"
                if "Cryptocurrency" in scan_result:
                    threat_info += "• **Crypto Scam**: Deze link is mogelijk een cryptocurrency-oplichting.\n"
                if "Suspicious" in scan_result:
                    threat_info += "• **Verdachte Link**: Deze link vertoont verdacht gedrag.\n"
                
                if not threat_info:
                    threat_info = "Deze link is als gevaarlijk gemarkeerd door ons beveiligingssysteem."
                    
                embed.add_field(
                    name="⚠️ Waarschuwing", 
                    value=threat_info,
                    inline=False
                )
                
                # Add safety tips
                embed.add_field(
                    name="🛡️ Veiligheidstips", 
                    value="• Klik nooit op verdachte links\n"
                          "• Deel geen persoonlijke informatie\n"
                          "• Gebruik een wachtwoordmanager\n"
                          "• Houd je software up-to-date",
                    inline=False
                )
                
                # Add timestamp
                embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
                
                # In Safe Display Mode, don't show the URL directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon URL (op eigen risico)", 
                        style=discord.ButtonStyle.danger,
                        url=url
                    ))
                    await interaction.followup.send(embed=embed, view=view)
                else:
                    # Show the URL in the description
                    embed.description = f"De URL `{url}` is gedetecteerd als {description}!"
                    await interaction.followup.send(embed=embed)
            else:
                embed = discord.Embed(
                    title="✅ URL SCAN RESULTAAT: VEILIG",
                    description=f"De URL lijkt veilig te zijn.",
                    color=discord.Color.green()
                )
                
                # Add a thumbnail for safe URL
                embed.set_thumbnail(url="https://i.imgur.com/5vMSsAg.png")  # Safe/shield icon
                
                # Add scan details
                embed.add_field(name="🔍 Scan Details", value=f"```{scan_result}```", inline=False)
                
                # Add safety reminder
                embed.add_field(
                    name="🛡️ Veiligheidsherinnering", 
                    value="Hoewel deze URL als veilig is gemarkeerd, wees altijd voorzichtig met links van onbekende bronnen.",
                    inline=False
                )
                
                # Add timestamp
                embed.timestamp = datetime.datetime.now(datetime.timezone.utc)
                
                # In Safe Display Mode, don't show the URL directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon URL", 
                        style=discord.ButtonStyle.primary,
                        url=url
                    ))
                    await interaction.followup.send(embed=embed, view=view)
                else:
                    # Show the URL in the description
                    embed.description = f"De URL `{url}` lijkt veilig te zijn."
                    await interaction.followup.send(embed=embed)
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for scanlink command: {e}")
            print(f"Error in scanlink slash command: {e}")
            # Delete the message after 30 seconds
            await message.delete(delay=30)
        else:
            embed = discord.Embed(
                title="✅ URL VEILIG",
                description=f"De URL `{url}` lijkt veilig te zijn.\n**Scan resultaat:** {scan_result}",
                color=discord.Color.green()
            )
            await message.edit(content=None, embed=embed)
            # Delete the message after 30 seconds
            await message.delete(delay=30)
            
    # Add a command to scan media
    # Keep the original prefix command for backward compatibility
    @bot.command(name="scanmedia")
    async def scan_media_prefix(ctx):
        # Check if there are any attachments
        if not ctx.message.attachments:
            await send_temp_message(ctx, "Gebruik: !scanmedia (met een bijgevoegde afbeelding of video)")
            return
        
        # Send a message indicating that the scan is in progress
        message = await ctx.send(f"🔍 Media wordt gescand, even geduld...")
        
        # Process each attachment
        for attachment in ctx.message.attachments:
            # Scan the media
            is_nsfw, scan_result, content_type = await scan_media_content(attachment)
            
            # Determine threat level based on scan result
            media_threat_level = "low"  # Default for safe content
            if is_nsfw:
                media_threat_level = "medium"  # Default for NSFW
                if "nudity: high" in scan_result.lower() or "explicit: high" in scan_result.lower():
                    media_threat_level = "high"
                elif "gore" in scan_result.lower() or "violence" in scan_result.lower():
                    media_threat_level = "critical"
            
            # Log the media scan with threat level
            print(f"[SCANMEDIA] Logging media scan to database with threat level: {media_threat_level}")
            await log_media_scan(ctx.author, attachment.url, is_nsfw, scan_result, content_type, media_threat_level)
            
            # Check if Safe Display Mode is enabled
            import dashboard_db as db
            safe_display_mode = db.is_safe_display_mode_enabled()
            
            # Update the message with the scan results
            if is_nsfw:
                embed = discord.Embed(
                    title="⚠️ ONGEPASTE MEDIA GEDETECTEERD",
                    description=f"De media is mogelijk ongepast!\n**Type:** {content_type}\n**Scan resultaat:** {scan_result}",
                    color=discord.Color.red()
                )
              
                # In Safe Display Mode, don't show the media directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon Media (Mogelijk Ongepast)", 
                        style=discord.ButtonStyle.danger,
                        url=attachment.url
                    ))
                    await message.edit(content=None, embed=embed, view=view)
                else:
                    # Add the image as a thumbnail if it's an image
                    if content_type == "image":
                        embed.set_thumbnail(url=attachment.url)
                    await message.edit(content=None, embed=embed)
            else:
                embed = discord.Embed(
                    title="✅ MEDIA SCAN VOLTOOID",
                    description=f"De media lijkt gepast.\n**Type:** {content_type}\n**Scan resultaat:** {scan_result}",
                    color=discord.Color.green()
                )
                
                # In Safe Display Mode, don't show the media directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon Media", 
                        style=discord.ButtonStyle.primary,
                        url=attachment.url
                    ))
                    await message.edit(content=None, embed=embed, view=view)
                else:
                    # Add the image as a thumbnail if it's an image
                    if content_type == "image":
                        embed.set_thumbnail(url=attachment.url)
                    await message.edit(content=None, embed=embed)
                
    # Add the slash command version
    @bot.tree.command(name="scanmedia", description="Scan een afbeelding of video op ongepaste inhoud")
    @discord.app_commands.describe(
        attachment="De afbeelding of video die je wilt scannen"
    )
    async def scan_media_slash(interaction: discord.Interaction, attachment: discord.Attachment):
        """Scan an image or video for inappropriate content"""
        try:
            # Send a message indicating that the scan is in progress
            await interaction.response.send_message(f"🔍 Media wordt gescand, even geduld...")
            
            # Scan the media
            is_nsfw, scan_result, content_type = await scan_media_content(attachment)
            
            # Determine threat level based on scan result
            media_threat_level = "low"  # Default for safe content
            if is_nsfw:
                media_threat_level = "medium"  # Default for NSFW
                if "nudity: high" in scan_result.lower() or "explicit: high" in scan_result.lower():
                    media_threat_level = "high"
                elif "gore" in scan_result.lower() or "violence" in scan_result.lower():
                    media_threat_level = "critical"
            
            # Log the media scan with threat level
            print(f"[SCANMEDIA SLASH] Logging media scan to database with threat level: {media_threat_level}")
            await log_media_scan(interaction.user, attachment.url, is_nsfw, scan_result, content_type, media_threat_level)
            
            # Check if Safe Display Mode is enabled
            import dashboard_db as db
            safe_display_mode = db.is_safe_display_mode_enabled()
            
            # Update the message with the scan results
            if is_nsfw:
                embed = discord.Embed(
                    title="⚠️ ONGEPASTE MEDIA GEDETECTEERD",
                    description=f"De media is mogelijk ongepast!\n**Type:** {content_type}\n**Scan resultaat:** {scan_result}",
                    color=discord.Color.red()
                )
                
                # In Safe Display Mode, don't show the media directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon Media (Mogelijk Ongepast)", 
                        style=discord.ButtonStyle.danger,
                        url=attachment.url
                    ))
                    await interaction.followup.send(embed=embed, view=view)
                else:
                    # Add the image as a thumbnail if it's an image
                    if content_type == "image":
                        embed.set_thumbnail(url=attachment.url)
                    await interaction.followup.send(embed=embed)
            else:
                embed = discord.Embed(
                    title="✅ MEDIA SCAN VOLTOOID",
                    description=f"De media lijkt gepast.\n**Type:** {content_type}\n**Scan resultaat:** {scan_result}",
                    color=discord.Color.green()
                )
                
                # In Safe Display Mode, don't show the media directly
                if safe_display_mode:
                    # Create a button view
                    view = discord.ui.View()
                    view.add_item(discord.ui.Button(
                        label="Toon Media", 
                        style=discord.ButtonStyle.primary,
                        url=attachment.url
                    ))
                    await interaction.followup.send(embed=embed, view=view)
                else:
                    # Add the image as a thumbnail if it's an image
                    if content_type == "image":
                        embed.set_thumbnail(url=attachment.url)
                    await interaction.followup.send(embed=embed)
        except Exception as e:
            # Handle any errors that might occur
            try:
                if not interaction.response.is_done():
                    await interaction.response.send_message(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
                else:
                    await interaction.followup.send(f"❌ Er is een fout opgetreden: {str(e)}", ephemeral=True)
            except:
                print(f"Could not send error message to user for scanmedia command: {e}")
            print(f"Error in scanmedia slash command: {e}")
    
    # Start the dashboard in a separate thread
    def run_dashboard():
        try:
            print("[DASHBOARD] 🔄 Initializing dashboard components...")
            
            # Make sure the templates and static directories exist
            script_dir = os.path.dirname(os.path.abspath(__file__))
            os.makedirs(os.path.join(script_dir, 'templates'), exist_ok=True)
            os.makedirs(os.path.join(script_dir, 'static'), exist_ok=True)
            os.makedirs(os.path.join(script_dir, 'static', 'css'), exist_ok=True)
            print("[DASHBOARD] ✅ Directory structure verified")
            
            # Initialize the database
            print("[DASHBOARD] 🔄 Initializing dashboard database...")
            import dashboard_db
            dashboard_db.init_db()
            print("[DASHBOARD] ✅ Database initialized successfully")
            
            # Start the Flask app
            print("[DASHBOARD] 🔄 Starting web server...")
            from dashboard import app, run_dashboard
            # Pass the bot to the dashboard
            run_dashboard(bot)
            # Make sure to bind to all interfaces
            print("[DASHBOARD] 🌐 Web server binding to all interfaces on port 5000")
            app.run(host='localhost', port=5000, debug=False, use_reloader=False)
        except Exception as e:
            print(f"[DASHBOARD] ❌ Error starting dashboard: {e}")
    
    # Function to get all guilds the bot is in
    def get_bot_guilds():
        """Get a list of all guilds the bot is in"""
        guilds = []
        for guild in bot.guilds:
            guilds.append({
                'guild_id': str(guild.id),
                'guild_name': guild.name
            })
        return guilds
    
    # Make the function accessible to the dashboard
    bot.get_bot_guilds = get_bot_guilds
    
    # Start the dashboard in a separate thread
    try:
        print("\n[DASHBOARD] Starting dashboard thread...")
        dashboard_thread = threading.Thread(target=run_dashboard)
        dashboard_thread.daemon = True  # This ensures the thread will exit when the main program exits
        dashboard_thread.start()
        print("[DASHBOARD] ✅ Dashboard successfully started!")
        print("[DASHBOARD] 🌐 Dashboard URL: http://192.168.0.2:5000")
        print("[DASHBOARD] 👤 Default login: admin / admin")
        print("[DASHBOARD] ⚠️ Remember to change the default password in Settings")
    except Exception as e:
        print(f"[DASHBOARD] ❌ Failed to start dashboard thread: {e}")
    
    # Define the moderation check task
    
    async def check_moderation_actions():
        """Check for moderation actions from the dashboard"""
        await bot.wait_until_ready()
        import dashboard_db as db
        import datetime
        import asyncio
        
        # Store the IDs of timeouts and bans we've seen
        known_timeout_ids = set()
        known_ban_ids = set()
        
        while not bot.is_closed():
            try:
                # Get current active timeouts
                current_timeouts = db.get_active_timeouts()
                current_timeout_ids = {timeout['id'] for timeout in current_timeouts}
                
                # Check for timeouts that were removed from the database
                removed_timeout_ids = known_timeout_ids - current_timeout_ids
                if removed_timeout_ids:
                    print(f"Detected {len(removed_timeout_ids)} timeouts to remove")
                    
                    # For each removed timeout, find the user and remove their timeout in Discord
                    for timeout_id in removed_timeout_ids:
                        # We don't have the timeout details anymore since it was removed
                        # So we need to check all guilds and members
                        for guild in bot.guilds:
                            try:
                                for member in guild.members:
                                    # Check if member is timed out by checking communication_disabled_until
                                    try:
                                        if hasattr(member, 'communication_disabled_until') and member.communication_disabled_until is not None:
                                            try:
                                                # Check if the bot has permission to moderate members
                                                bot_member = guild.get_member(bot.user.id)
                                                if not bot_member.guild_permissions.moderate_members:
                                                    print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Moderate Members' permissie in {guild.name}!")
                                                    print("Ga naar Server Instellingen > Rollen > [Bot Rol] > Permissies en schakel 'Leden modereren' in.")
                                                    
                                                    # Try to send a message to the guild owner
                                                    try:
                                                        if guild.owner:
                                                            await guild.owner.send(f"⚠️ **BELANGRIJKE MELDING**: De bot heeft geen 'Moderate Members' permissie in **{guild.name}**!\n\n"
                                                                                  f"Hierdoor kan de bot geen timeouts verwijderen.\n\n"
                                                                                  f"**Hoe los je dit op:**\n"
                                                                                  f"1. Ga naar Server Instellingen > Rollen\n"
                                                                                  f"2. Klik op de rol van de bot\n"
                                                                                  f"3. Schakel de permissie 'Leden modereren' in\n\n"
                                                                                  f"Als je hulp nodig hebt, neem contact op met de bot ontwikkelaar.")
                                                    except:
                                                        print("Kon geen DM sturen naar de server eigenaar")
                                                    continue
                                                
                                                # Remove the timeout by setting it to None
                                                await member.timeout(None, reason="Timeout removed via dashboard")
                                                print(f"Removed timeout for {member} in {guild}")
                                            except discord.errors.Forbidden:
                                                print(f"⚠️ PERMISSIE FOUT: Kan timeout niet verwijderen voor {member} in {guild.name}. De bot heeft niet genoeg rechten.")
                                                print("Zorg ervoor dat de bot rol hoger staat dan de rol van de gebruiker en dat de bot 'Moderate Members' permissie heeft.")
                                            except Exception as e:
                                                print(f"Error removing timeout for {member}: {e}")
                                    except AttributeError:
                                        # Skip members that don't have the required attributes
                                        continue
                            except Exception as e:
                                print(f"Error processing guild {guild} for timeouts: {e}")
                
                # Check for new timeouts that were added to the database
                new_timeout_ids = current_timeout_ids - known_timeout_ids
                if new_timeout_ids:
                    print(f"Detected {len(new_timeout_ids)} new timeouts to apply")
                    
                    # For each new timeout, find the user and apply the timeout in Discord
                    for timeout in current_timeouts:
                        if timeout['id'] in new_timeout_ids:
                            try:
                                # Get the guild and member
                                guild = bot.get_guild(int(timeout['guild_id']))
                                if guild:
                                    # Try to get member by ID
                                    try:
                                        member = guild.get_member(int(timeout['user_id']))
                                    except ValueError:
                                        # If user_id is not a valid integer, try to find by name
                                        member = discord.utils.get(guild.members, name=timeout['user_id'])
                                        
                                    if member:
                                        # Parse the timeout_until string to a datetime
                                        try:
                                            timeout_until = datetime.datetime.fromisoformat(timeout['timeout_until'])
                                            
                                            # Calculate the duration
                                            now = datetime.datetime.now(datetime.UTC)
                                            duration = timeout_until - now
                                            
                                            # Apply the timeout if the duration is positive
                                            if duration.total_seconds() > 0:
                                                # Check if the bot has permission to moderate members
                                                bot_member = guild.get_member(bot.user.id)
                                                if not bot_member.guild_permissions.moderate_members:
                                                    print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Moderate Members' permissie in {guild.name}!")
                                                    print("Ga naar Server Instellingen > Rollen > [Bot Rol] > Permissies en schakel 'Leden modereren' in.")
                                                    
                                                    # Try to send a message to the guild owner
                                                    try:
                                                        if guild.owner:
                                                            await guild.owner.send(f"⚠️ **BELANGRIJKE MELDING**: De bot heeft geen 'Moderate Members' permissie in **{guild.name}**!\n\n"
                                                                                  f"Hierdoor kan de bot geen timeouts toepassen op gebruikers die de regels overtreden.\n\n"
                                                                                  f"**Hoe los je dit op:**\n"
                                                                                  f"1. Ga naar Server Instellingen > Rollen\n"
                                                                                  f"2. Klik op de rol van de bot\n"
                                                                                  f"3. Schakel de permissie 'Leden modereren' in\n\n"
                                                                                  f"Als je hulp nodig hebt, neem contact op met de bot ontwikkelaar.")
                                                    except:
                                                        print("Kon geen DM sturen naar de server eigenaar")
                                                    continue
                                                
                                                # Check if the member can be timed out
                                                if member.guild_permissions.administrator:
                                                    print(f"Kan gebruiker {member} niet time-outen omdat deze administrator permissies heeft")
                                                    continue
                                                
                                                try:
                                                    # Convert duration to timedelta for the timeout method
                                                    duration_td = datetime.timedelta(seconds=duration.total_seconds())
                                                    await member.timeout(duration_td, reason=timeout['reason'] or "Timeout applied via dashboard")
                                                    print(f"Applied timeout for {member} in {guild} until {timeout_until}")
                                                except discord.errors.Forbidden:
                                                    print(f"⚠️ PERMISSIE FOUT: Kan gebruiker {member} niet time-outen in {guild.name}. De bot heeft niet genoeg rechten.")
                                                    print("Zorg ervoor dat de bot rol hoger staat dan de rol van de gebruiker en dat de bot 'Moderate Members' permissie heeft.")
                                            else:
                                                print(f"Timeout for {member} in {guild} has already expired")
                                        except Exception as e:
                                            print(f"Error parsing timeout date or applying timeout: {e}")
                                            try:
                                                # Try a default timeout duration of 1 day as fallback
                                                default_duration = datetime.timedelta(days=1)
                                                
                                                # Check if the bot has permission to moderate members
                                                bot_member = guild.get_member(bot.user.id)
                                                if not bot_member.guild_permissions.moderate_members:
                                                    print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Moderate Members' permissie in {guild.name}!")
                                                    continue
                                                
                                                await member.timeout(default_duration, reason=timeout['reason'] or "Timeout applied via dashboard (default duration)")
                                                print(f"Applied default timeout for {member} in {guild} for 1 day")
                                            except discord.errors.Forbidden:
                                                print(f"⚠️ PERMISSIE FOUT: Kan gebruiker {member} niet time-outen in {guild.name}. De bot heeft niet genoeg rechten.")
                                    else:
                                        print(f"Could not find member {timeout['user_id']} in guild {guild.name}")
                                else:
                                    print(f"Could not find guild {timeout['guild_id']}")
                            except Exception as e:
                                print(f"Error applying timeout: {e}")
                
                # Update known timeout IDs
                known_timeout_ids = current_timeout_ids
                
                # Get current bans
                current_bans = db.get_banned_users()
                current_ban_ids = {ban['id'] for ban in current_bans}
                
                # Check for bans that were removed from the database
                removed_ban_ids = known_ban_ids - current_ban_ids
                if removed_ban_ids:
                    print(f"Detected {len(removed_ban_ids)} bans to remove")
                    
                    # For each removed ban, find the user and unban them in Discord
                    # Since we don't have the ban details anymore, we need to check all guilds
                    for guild in bot.guilds:
                        try:
                            # Get all bans for this guild
                            bans = [ban async for ban in guild.bans()]
                            
                            # For each ban, check if it should be removed
                            for ban_entry in bans:
                                try:
                                    # Unban the user
                                    await guild.unban(ban_entry.user, reason="Unbanned via dashboard")
                                    print(f"Unbanned {ban_entry.user} from {guild}")
                                except Exception as e:
                                    print(f"Error unbanning user: {e}")
                        except Exception as e:
                            print(f"Error getting bans for guild {guild}: {e}")
                
                # Update known ban IDs
                known_ban_ids = current_ban_ids
                
                # Check for new bans that were added to the database
                new_ban_ids = current_ban_ids - known_ban_ids
                if new_ban_ids:
                    print(f"Detected {len(new_ban_ids)} new bans to apply")
                    
                    # For each new ban, find the user and apply the ban in Discord
                    for ban in current_bans:
                        if ban['id'] in new_ban_ids:
                            try:
                                # Get the guild
                                guild = bot.get_guild(int(ban['guild_id']))
                                if guild:
                                    # Try to get the user
                                    try:
                                        # Try to get user by ID
                                        try:
                                            # First check if the user is already banned
                                            try:
                                                bans = [ban_entry async for ban_entry in guild.bans()]
                                                already_banned = any(str(ban_entry.user.id) == ban['user_id'] for ban_entry in bans)
                                                
                                                if already_banned:
                                                    print(f"User {ban['user_id']} is already banned from {guild}")
                                                    continue
                                            except Exception as e:
                                                print(f"Error checking existing bans: {e}")
                                            
                                            # Try to get user by ID
                                            try:
                                                user = await bot.fetch_user(int(ban['user_id']))
                                                # Ban the user
                                                await guild.ban(user, reason=ban['reason'] or "Ban applied via dashboard", delete_message_days=0)
                                                print(f"Banned {user} from {guild}")
                                            except ValueError:
                                                # If user_id is not a valid integer, try to find by name
                                                member = discord.utils.get(guild.members, name=ban['user_id'])
                                                if member:
                                                    await guild.ban(member, reason=ban['reason'] or "Ban applied via dashboard", delete_message_days=0)
                                                    print(f"Banned {member} from {guild}")
                                                else:
                                                    print(f"Could not find user {ban['user_id']} in guild {guild.name}")
                                        except discord.errors.Forbidden:
                                            print(f"Bot does not have permission to ban users in {guild}")
                                        except discord.errors.HTTPException as e:
                                            print(f"HTTP error banning user {ban['user_id']}: {e}")
                                    except Exception as e:
                                        print(f"Error banning user {ban['user_id']}: {e}")
                                else:
                                    print(f"Could not find guild {ban['guild_id']}")
                            except Exception as e:
                                print(f"Error applying ban: {e}")
                
                # Check for mutes
                try:
                    # Get current mutes
                    current_mutes = db.get_muted_users()
                    current_mute_ids = {mute['id'] for mute in current_mutes}
                    
                    # Store known mute IDs if not already stored
                    if not hasattr(check_moderation_actions, 'known_mute_ids'):
                        check_moderation_actions.known_mute_ids = set()
                    
                    # Check for mutes that were removed from the database
                    removed_mute_ids = check_moderation_actions.known_mute_ids - current_mute_ids
                    if removed_mute_ids:
                        print(f"Detected {len(removed_mute_ids)} mutes to remove")
                        
                        # For each removed mute, find the user and unmute them in Discord
                        # We need to get the old mute details from our stored data
                        old_mutes = []
                        for mute_id in removed_mute_ids:
                            # Find the mute in our previous known mutes
                            for guild in bot.guilds:
                                try:
                                    # Get the muted role
                                    muted_role = discord.utils.get(guild.roles, name="Muted")
                                    if not muted_role:
                                        continue
                                        
                                    # Check all members with the muted role
                                    for member in guild.members:
                                        if muted_role in member.roles:
                                            try:
                                                # Remove the muted role
                                                await member.remove_roles(muted_role, reason="Unmuted via dashboard")
                                                print(f"Unmuted {member} in {guild}")
                                            except discord.errors.Forbidden:
                                                print(f"Bot does not have permission to remove roles in {guild}")
                                            except Exception as e:
                                                print(f"Error unmuting user {member}: {e}")
                                except Exception as e:
                                    print(f"Error processing guild {guild} for unmutes: {e}")
                    
                    # Check for new mutes that were added to the database
                    new_mute_ids = current_mute_ids - check_moderation_actions.known_mute_ids
                    if new_mute_ids:
                        print(f"Detected {len(new_mute_ids)} new mutes to apply")
                        
                        # For each new mute, find the user and apply the mute in Discord
                        for mute in current_mutes:
                            if mute['id'] in new_mute_ids:
                                try:
                                    # Get the guild
                                    guild = bot.get_guild(int(mute['guild_id']))
                                    if guild:
                                        # Try to get member by ID
                                        try:
                                            member = guild.get_member(int(mute['user_id']))
                                        except ValueError:
                                            # If user_id is not a valid integer, try to find by name
                                            member = discord.utils.get(guild.members, name=mute['user_id'])
                                            
                                        if member:
                                            # Check if already muted
                                            muted_role = discord.utils.get(guild.roles, name="Muted")
                                            if muted_role and muted_role in member.roles:
                                                print(f"User {member} is already muted in {guild}")
                                                continue
                                                
                                            # Get or create the muted role
                                            if not muted_role:
                                                # Create the muted role
                                                try:
                                                    print(f"Creating Muted role in {guild}")
                                                    muted_role = await guild.create_role(
                                                        name="Muted",
                                                        reason="Created for mute system",
                                                        color=discord.Color.dark_gray()
                                                    )
                                                    
                                                    # Set permissions for the muted role for all channels
                                                    print(f"Setting permissions for Muted role in {guild}")
                                                    for channel in guild.channels:
                                                        try:
                                                            # Different permissions based on channel type
                                                            if isinstance(channel, discord.TextChannel):
                                                                await channel.set_permissions(
                                                                    muted_role,
                                                                    send_messages=False,
                                                                    add_reactions=False,
                                                                    create_public_threads=False,
                                                                    create_private_threads=False,
                                                                    send_messages_in_threads=False
                                                                )
                                                            elif isinstance(channel, discord.VoiceChannel):
                                                                await channel.set_permissions(
                                                                    muted_role,
                                                                    speak=False,
                                                                    stream=False,
                                                                    connect=True
                                                                )
                                                            elif isinstance(channel, discord.CategoryChannel):
                                                                await channel.set_permissions(
                                                                    muted_role,
                                                                    send_messages=False,
                                                                    speak=False,
                                                                    add_reactions=False
                                                                )
                                                        except Exception as e:
                                                            print(f"Error setting permissions for channel {channel}: {e}")
                                                except Exception as e:
                                                    print(f"Error creating muted role: {e}")
                                                    continue
                                            
                                            # Apply the muted role
                                            try:
                                                await member.add_roles(muted_role, reason=mute['reason'] or "Muted via dashboard")
                                                print(f"Muted {member} in {guild}")
                                            except discord.errors.Forbidden:
                                                print(f"Bot does not have permission to add roles in {guild}")
                                            except Exception as e:
                                                print(f"Error adding muted role to {member}: {e}")
                                        else:
                                            print(f"Could not find member {mute['user_id']} in guild {guild.name}")
                                    else:
                                        print(f"Could not find guild {mute['guild_id']}")
                                except Exception as e:
                                    print(f"Error applying mute: {e}")
                    
                    # Update known mute IDs
                    check_moderation_actions.known_mute_ids = current_mute_ids
                    
                except Exception as e:
                    print(f"Error handling mutes: {e}")
                
            except Exception as e:
                print(f"Error checking moderation actions: {e}")
            
            # Check every 30 seconds
            await asyncio.sleep(30)
    
    # Run the bot
    print("\n[BOT] 🚀 Starting Silcas Bot...")
    print("[BOT] ⏳ Connecting to Discord API...")
    
    # Print startup information in a more structured way
    print("\n┌─────────────────────────────────────────────────────┐")
    print("│               SILCAS BOT OPSTARTPROCES               │")
    print("├─────────────────────────────────────────────────────┤")
    print("│ ✅ Dashboard gestart en bereikbaar                   │")
    print("│ ⏳ Bot wordt nu verbonden met Discord                │")
    print("│ 🔄 Slash commands worden geregistreerd               │")
    print("│ 🛡️ Beveiligingsmodules worden geladen                │")
    print("└─────────────────────────────────────────────────────┘")
    
    print("\n[BOT] 📋 Checklist voor probleemoplossing:")
    
    print("\n[BOT] 🔑 Privileged Intents:")
    print("  ├─ Ga naar: https://discord.com/developers/applications")
    print("  ├─ Selecteer je bot applicatie → 'Bot' tab")
    print("  ├─ Scroll naar 'Privileged Gateway Intents'")
    print("  └─ Schakel 'SERVER MEMBERS INTENT' en 'MESSAGE CONTENT INTENT' in")
    
    print("\n[BOT] 🔗 Slash Commands Niet Zichtbaar?")
    print("  ├─ Controleer scopes: 'bot' EN 'applications.commands'")
    print("  ├─ Gebruik /sync commando in Discord")
    print("  └─ Wacht tot een uur voor globale commands")
    
    print("\n[BOT] ⚠️ Permissie Problemen (Error 403):")
    print("  ├─ Controleer bot permissies: Moderate Members, Ban Members, etc.")
    print("  ├─ Zorg dat de bot rol HOGER staat in de rollenlijst")
    print("  └─ Bot kan geen actie uitvoeren op gebruikers met hogere rechten")
    
    print("\n[BOT] 🔍 Permissie Check:")
    print("  └─ De bot zal server eigenaren informeren over ontbrekende permissies")
    
    print("\n[BOT] 🔄 Bot wordt nu gestart...")
    bot.run(TOKEN)

except ModuleNotFoundError as e:
    if "audioop" in str(e):
        print("\nERROR: Python 3.13 is not fully compatible with discord.py")
        print("Please install Python 3.11 from: https://www.python.org/downloads/release/python-3118/")
        print("After installing Python 3.11, run:")
        print("pip install discord.py python-dotenv")
        print("Then run this script again with Python 3.11")
    else:
        print(f"\nERROR: Missing module: {e}")
        print("Try installing required packages:")
        print("pip install discord.py python-dotenv")
    sys.exit(1)
except Exception as e:
    print(f"\nERROR: {e}")
    sys.exit(1)