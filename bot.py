//yo

import logging
import os

import discord
from discord.ext import commands
from dotenv import load_dotenv

from scam_detector import detect_scam, extract_image_text


load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scam_guard")

TOKEN = os.getenv("DISCORD_TOKEN")
REPORT_CHANNEL_ID = int(os.getenv("REPORT_CHANNEL_ID", "0"))
AUTO_DELETE = os.getenv("AUTO_DELETE", "false").lower() == "true"
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGES_PER_MESSAGE = 3

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready() -> None:
    logger.info("Logged in as %s", bot.user)


async def _read_image(attachment: discord.Attachment) -> bytes | None:
    if attachment.size > MAX_IMAGE_BYTES:
        logger.info("Skipping oversized image attachment %s", attachment.filename)
        return None
    try:
        return await attachment.read()
    except (discord.HTTPException, discord.Forbidden):
        logger.exception("Could not read image attachment %s", attachment.filename)
        return None


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot or message.guild is None:
        return

    scanned_text = [message.content]
    image_attachments = [
        attachment
        for attachment in message.attachments
        if attachment.content_type
        and attachment.content_type.startswith("image/")
    ][:MAX_IMAGES_PER_MESSAGE]

    for attachment in image_attachments:
        image_bytes = await _read_image(attachment)
        if image_bytes is None:
            continue
        try:
            image_text = extract_image_text(image_bytes)
        except Exception:
            logger.exception("OCR failed for image attachment %s", attachment.filename)
            continue
        if image_text.strip():
            scanned_text.append(image_text)

    detection = detect_scam("\n".join(scanned_text))
    if not detection.is_scam:
        return

    logger.warning(
        "Possible scam in guild=%s channel=%s author=%s score=%d reasons=%s",
        message.guild.id,
        message.channel.id,
        message.author,
        detection.score,
        ", ".join(detection.reasons),
    )

    report_channel = bot.get_channel(REPORT_CHANNEL_ID) if REPORT_CHANNEL_ID else None
    if isinstance(report_channel, discord.TextChannel):
        embed = discord.Embed(
            title="Possible giveaway scam detected",
            color=discord.Color.orange(),
            description=(
                f"**Author:** {message.author.mention} (`{message.author.id}`)\n"
                f"**Channel:** {message.channel.mention}\n"
                f"**Signals:** {', '.join(detection.reasons)}\n"
                f"**Score:** {detection.score}"
            ),
        )
        embed.add_field(
            name="Message",
            value=(message.content[:900] or "No text; flagged from image OCR.")[:1024],
            inline=False,
        )
        embed.add_field(name="Review", value=f"[Open message]({message.jump_url})", inline=False)
        try:
            await report_channel.send(embed=embed)
        except (discord.HTTPException, discord.Forbidden):
            logger.exception("Could not post scam report")

    if AUTO_DELETE:
        try:
            await message.delete()
        except (discord.HTTPException, discord.Forbidden):
            logger.exception("Could not delete flagged message")


if not TOKEN:
    raise RuntimeError("Set DISCORD_TOKEN or .env file")

bot.run(TOKEN)
