#!/usr/bin/env python

import logging
import math
import random
import struct
import time
import wave
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.threads import start_thread

LOG = logging.getLogger(__name__)

scale_notes = {
    # pitch standard A440 ie a4 = 440Hz
    "c": 16.35,
    "C": 17.32,
    "d": 18.35,
    "D": 19.45,
    "e": 20.6,
    "f": 21.83,
    "F": 23.12,
    "g": 24.5,
    "G": 25.96,
    "a": 27.5,
    "A": 29.14,
    "b": 30.87,
}


class AudioHandlerThread:
    def __init__(self, path: Path, queue: Queue):

        self.writer = Writer(path)
        self.queue = queue

    def run(self, params):
        LOG.debug("starting audio processing thread")
        while True:
            msg = self.queue.get()
            # termination condition
            if not msg:
                LOG.debug("got shutdown message")
                self.writer.close()
                break

            (service_name, now) = msg
            self.writer.add_service_beep(service_name, now=now)


class AudioHandler:
    def __init__(self, path: str | Path):
        LOG.info("setting up audio handler, writing to %s", path)
        self.queue = Queue()
        self.handler_thread = AudioHandlerThread(Path(path), self.queue)

        def _shutdown(params):
            LOG.debug("flushing audio file")
            self.queue.put(None)

        self.writer_thread = start_thread(
            method=self.handler_thread.run,
            name="audio-handler",
            on_stop=_shutdown,
            _shutdown_hook=True,
        )

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        service_name = context.service.service_name
        LOG.debug("enqueueing audio request for service %s", service_name)
        self.queue.put((service_name, datetime.now(tz=timezone.utc)))


def note_frequency(note: str, octave: int):
    return scale_notes[note] * 2**octave


class Writer:
    _wav: wave.Wave_write
    _last_time: datetime | None

    def __init__(self, output_file: Path, sample_rate: float = 44100.0):
        self.sample_rate = sample_rate
        self.output_file = output_file
        self.output_file.parent.mkdir(exist_ok=True, parents=True)
        self._wav = wave.open(str(self.output_file), "w")
        self._wav.setnchannels(1)
        self._wav.setsampwidth(2)
        self._wav.setcomptype("NONE", "not compressed")
        self._wav.setframerate(self.sample_rate)
        self._last_time = None
        self._service_note_cache = {}

    def add_service_beep(self, service_name: str, now: datetime | None = None):
        if service_name not in self._service_note_cache:
            note = random.choice(list(scale_notes.keys()))
            octave = random.choice([4, 5, 6])
            self._service_note_cache[service_name] = (note, octave)

        note, octave = self._service_note_cache[service_name]
        self.add_beep(note, octave, now=now)

    def add_beep(self, note: str, octave: int, now: datetime | None = None):
        now = now or datetime.now(tz=timezone.utc)
        self._fill_with_silence(now)
        freq = note_frequency(note, octave)
        self._append_sinewave(freq)
        self._last_time = now

    def close(self):
        self._wav.close()

    def _fill_with_silence(self, now: datetime):
        if self._last_time is None:
            self._last_time = now
            return

        duration = (now - self._last_time).total_seconds() * 1000
        self._append_silence(int(duration))
        self._last_time = now

    def _append_silence(self, duration_milliseconds: int):
        if not self._wav:
            raise RuntimeError("not open")

        num_samples = duration_milliseconds * (self.sample_rate / 1000.0)
        for _ in range(int(num_samples)):
            self._wav.writeframes(struct.pack("h", 0))

    def _append_sinewave(
        self, freq: float = 440.0, duration_milliseconds: int = 100, volume: float = 1.0
    ):
        if not self._wav:
            raise RuntimeError("not open")

        num_samples = duration_milliseconds * (self.sample_rate / 1000.0)
        for x in range(int(num_samples)):
            value = volume * math.sin(2 * math.pi * freq * (x / self.sample_rate))
            self._wav.writeframes(struct.pack("h", int(value * 32767.0)))

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self._wav.close()


if __name__ == "__main__":
    with Writer(Path.cwd() / "output.wav") as outfile:
        outfile.add_beep("a", 4)
        time.sleep(1)
        outfile.add_beep("b", 4)
