"""Discord: .deobf + one Lua/text attachment. Requires discord.py, Node 22+ and Lua 5.1 compiler."""
import asyncio
import hashlib
import shutil
import os
import tempfile
import time
from collections import OrderedDict
from pathlib import Path

import discord
from discord.ext import commands

DEOBF_DIR = Path(os.environ.get(
    "DEOBF_RECOVER_DIR", str(Path(__file__).resolve().parent / "prometheus-recover")
)).resolve()
MAX_INPUT = 2 * 1024 * 1024
BUSY = asyncio.Lock()


class ProcessingError(Exception):
    pass


class ResultCache:
    """Keep a bounded set of successful results for this bot session."""

    def __init__(self, max_bytes=64 * 1024 * 1024, max_entries=64):
        self.max_bytes = max_bytes
        self.max_entries = max_entries
        self.entries = OrderedDict()
        self.size = 0

    def get(self, key):
        value = self.entries.get(key)
        if value is not None:
            self.entries.move_to_end(key)
        return value

    def put(self, key, value):
        if len(value) > self.max_bytes:
            return
        old = self.entries.pop(key, None)
        if old is not None:
            self.size -= len(old)
        self.entries[key] = value
        self.size += len(value)
        while self.size > self.max_bytes or len(self.entries) > self.max_entries:
            _, removed = self.entries.popitem(last=False)
            self.size -= len(removed)


async def delayed_progress(ctx):
    await asyncio.sleep(1)
    await ctx.send("Procesando…")


class Deobfuscator:
    """Run the pinned recovery CLI and return only the Lua source."""

    def __init__(self, repo=None):
        self.repo = Path(repo or DEOBF_DIR).resolve()
        self.node = shutil.which("node")
        self.luac = shutil.which("luac5.1") or shutil.which("luac51") or shutil.which("luac-5.1")
        self.process = None
        self.lock = asyncio.Lock()
        self.closed = False
        self.environment = {"PATH": os.defpath, "LANG": "C.UTF-8"}

    async def prepare(self):
        if not self.node or not self.luac:
            raise ProcessingError("Ejecuta la primera celda: faltan Node o luac5.1.")
        if not (self.repo / "bin/recover.js").is_file():
            raise ProcessingError("Ejecuta la primera celda para descargar el motor.")
        for command, valid in [
            ([self.node, "--version"], lambda v: int(v.strip().lstrip(b"v").split(b".")[0]) >= 22),
            ([self.luac, "-v"], lambda v: v.startswith(b"Lua 5.1")),
        ]:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=self.environment)
            try:
                version, _ = await asyncio.wait_for(process.communicate(), 10)
                if process.returncode or not valid(version):
                    raise ProcessingError("Se necesitan Node 22+ y Lua 5.1. Ejecuta la primera celda.")
            finally:
                if process.returncode is None:
                    process.kill()
                await process.wait()

    async def _stop(self):
        process, self.process = self.process, None
        if process is not None:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()

    async def run(self, source, timeout=75):
        async with self.lock:
            if self.closed:
                raise ProcessingError("Reinicia el bot antes de procesar otro archivo.")
            with tempfile.TemporaryDirectory(prefix="recover-") as folder, tempfile.TemporaryFile() as log:
                destination = Path(folder) / "result"
                process = await asyncio.create_subprocess_exec(
                    self.node, "--max-old-space-size=2048", str(self.repo / "bin/recover.js"),
                    str(source.resolve()), "-o", str(destination), "--luac", self.luac,
                    "--timeout", "30000",
                    cwd=str(source.parent), env=self.environment, stdout=log, stderr=log,
                )
                self.process = process
                try:
                    if self.closed:
                        raise ProcessingError("El bot se está cerrando.")
                    await asyncio.wait_for(process.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    raise ProcessingError("El archivo superó el tiempo permitido.") from None
                finally:
                    await self._stop()
                if process.returncode not in (0, 2):
                    raise ProcessingError("El motor no pudo analizar este archivo Lua/Prometheus.")
                filename = "recovered.lua" if process.returncode == 0 else "partial.lua"
                result = destination / filename
                if result.stat().st_size > 32 * 1024 * 1024:
                    raise ProcessingError("El resultado supera el límite de 32 MiB.")
                # Devuelve el resultado directamente y evita una copia intermedia en disco.
                return result.read_bytes()

    async def close(self):
        self.closed = True
        await self._stop()


class DeobfBot(commands.Bot):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.engine = Deobfuscator()

    async def setup_hook(self):
        await self.engine.prepare()

    async def close(self):
        try:
            await super().close()
        finally:
            await self.engine.close()


def create_bot(owner_id):
    cache = ResultCache()
    intents = discord.Intents.default()
    intents.message_content = True
    bot = DeobfBot(
        command_prefix=".", intents=intents, help_command=None,
        allowed_mentions=discord.AllowedMentions.none(),
    )
    @bot.event
    async def on_ready():
        print(f"Prometheus Recover conectado como {bot.user}. Envía .deobf con un archivo .lua o .txt.")

    @bot.command(name="deobf")
    async def deobf(ctx):
        if ctx.author.id != owner_id:
            return
        attachments = ctx.message.attachments
        if len(attachments) != 1 or not attachments[0].filename.lower().endswith((".lua", ".txt")):
            await ctx.send("Envía `.deobf` y adjunta un único archivo `.lua` o `.txt` en ese mensaje.")
            return
        attachment = attachments[0]
        if attachment.size > MAX_INPUT:
            await ctx.send("El archivo debe pesar como máximo 2 MiB.")
            return
        if BUSY.locked():
            await ctx.send("Estoy procesando otro archivo. Inténtalo cuando termine.")
            return
        async with BUSY:
            started = time.perf_counter()
            progress = asyncio.create_task(delayed_progress(ctx))
            try:
                input_data = await asyncio.wait_for(attachment.read(), timeout=30)
                if len(input_data) > MAX_INPUT:
                    raise ProcessingError("El archivo debe pesar como máximo 2 MiB.")
                key = hashlib.sha256(input_data).digest()
                cached = cache.get(key)
                if cached is not None:
                    # Cache hit: avoid creating a temp directory and writing the result to disk.
                    result_data = cached
                else:
                    with tempfile.TemporaryDirectory(prefix="deobf-") as folder:
                        source = Path(folder) / "entrada.lua"
                        source.write_bytes(input_data)
                        result_data = await bot.engine.run(source)
                    if len(result_data) <= cache.max_bytes:
                        cache.put(key, result_data)
                upload_limit = ctx.guild.filesize_limit if ctx.guild else 10 * 1024 * 1024
                if len(result_data) > upload_limit:
                    raise ProcessingError("El resultado supera el límite de archivos de Discord.")
                progress.cancel()
                await asyncio.gather(progress, return_exceptions=True)
                elapsed = time.perf_counter() - started
                detail = " (desde caché)" if cached is not None else ""
                import io
                downloadable = discord.File(io.BytesIO(result_data), filename="resultado.lua")
                try:
                    await ctx.send(
                        f"Resultado en {elapsed:.2f} s{detail}:",
                        file=downloadable,
                    )
                finally:
                    downloadable.close()
            except ProcessingError as error:
                await ctx.send(str(error))
            except asyncio.TimeoutError:
                await ctx.send("La descarga del adjunto tardó demasiado. Inténtalo de nuevo.")
            except Exception:
                await ctx.send("No pude completar la operación. Revisa el archivo y los permisos del bot.")
            finally:
                progress.cancel()
                await asyncio.gather(progress, return_exceptions=True)

    return bot


async def main():
    token = os.environ.get("DISCORD_TOKEN", "")
    owner = os.environ.get("DISCORD_OWNER_ID", "")
    if not token or not owner.isdecimal():
        raise RuntimeError("Configura DISCORD_TOKEN y DISCORD_OWNER_ID antes de iniciar.")
    if not (DEOBF_DIR / "bin" / "recover.js").is_file():
        raise RuntimeError("No se encuentra la herramienta. Revisa DEOBF_RECOVER_DIR.")
    bot = create_bot(int(owner))
    async with bot:
        await bot.start(token)


if __name__ == "__main__":
    asyncio.run(main())
