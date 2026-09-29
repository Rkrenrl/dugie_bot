# DugieBro scam detection bot

A small Discord bot that checks message text and OCR-scans image attachments for common MrBeast giveaway and free Nitro scams. It reports likely matches to a moderator channel for review. Detection is heuristic, so review reports before taking action.

## Requirements

- Python 3.10 or newer
- Tesseract OCR installed on the host
- A Discord application with a bot user

On Debian or Kali, Linux, install the OCR engine with `sudo apt install tesseract-ocr`.

## Setup

1. In the Discord Developer Portal, enable the **Message Content Intent** for the bot.
2. Invite the bot with `View Channels`, `Read Message History`, `Send Messages`, and `Embed Links`. Add `Manage Messages` only if you intentionally enable automatic deletion.
3. Install dependencies: `python -m pip install -r requirements.txt`.
4. Copy `.env.example` to `.env`; set `DISCORD_TOKEN`
5. Start it with `python bot.py`.

Keep `.env` private and never post your bot token. If `REPORT_CHANNEL_ID` is unset or inaccessible, detections are written to the bot's log. `AUTO_DELETE` defaults to `false`; set it to `true` only if you want flagged messages deleted automatically and the bot has `Manage Messages` permission.

## Tests

Run `python -m unittest discover -s tests`.

The detector checks MrBeast or scam giveaway branding, free Nitro offers, prize/claim language, and suspicious giveaway-related domains. It scans up to three image attachments per message, up to 5 MB each. OCR quality depends on image clarity and Tesseract language data.
