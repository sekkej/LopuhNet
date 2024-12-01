import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

import pyaudio
import wave
import threading
import time
from shared.shared_utils import CHAKEM

# Parameters
FORMAT = pyaudio.paInt16             # 16-bit resolution
CHANNELS = 1                         # Mono audio
RATE = 44100                         # 44.1kHz sampling rate
CHUNK = 1024                         # Buffer size in frames
RECORD_SECONDS = 3                   # Duration of recording
WAVE_OUTPUT_FILENAME = "output.wav"  # File to save the recording

c1_public, c1_private = CHAKEM.generate_keys()
c2_public, c2_private = CHAKEM.generate_keys()

audio = pyaudio.PyAudio()

# Open a stream for input from the microphone
stream_in = audio.open(format=FORMAT,
                       channels=CHANNELS,
                       rate=RATE,
                       input=True,
                       frames_per_buffer=CHUNK)

# Open a stream for output to the speakers
stream_out = audio.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        output=True,
                        frames_per_buffer=CHUNK)

print("Recording and Playing Back...")
# curframe = None

# def streamout_write(frames: list[bytes]):
#     print("sw")
#     for frame in frames:
#         stream_out.write(frame)

# def sender():
#     while True:
#         data = stream_in.read(CHUNK)
#         encrypted, ciphertext, nonce = CHAKEM.encrypt(data, c2_public, b'audiostreaming-test')
#         yield encrypted, ciphertext, nonce

# def output():
#     time.sleep(.1)
#     chunk = []
#     for encrypted, ciphertext, nonce in sender():
#         decrypted = CHAKEM.decrypt(encrypted, c2_private, ciphertext, nonce, b'audiostreaming-test')
#         chunk.append(decrypted)
#         if len(chunk) % 128 == 0:
#             threading.Thread(target=streamout_write, args=(chunk.clear,)).start()
#             chunk.clear()

# output()
# curframe = None

# Record and play back audio data in real-time
eframes = []

for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
    data = stream_in.read(CHUNK)
    # stream_out.write(data)  # Play back the audio
    eframes.append(CHAKEM.encrypt(data, c2_public, b'audiostreaming-test'))

print("Finished recording and playback.")

frames = []

for encrypted, ciphertext, nonce in eframes:
    frames.append(CHAKEM.decrypt(encrypted, c2_private, ciphertext, nonce, b'audiostreaming-test'))

# Stop and close the streams
stream_in.stop_stream()
stream_in.close()
stream_out.stop_stream()
stream_out.close()
audio.terminate()

# Save the recorded audio to a file
with wave.open(WAVE_OUTPUT_FILENAME, 'wb') as wf:
    wf.setnchannels(CHANNELS)
    wf.setsampwidth(audio.get_sample_size(FORMAT))
    wf.setframerate(RATE)
    wf.writeframes(b''.join(frames))

print(f"Audio saved to {WAVE_OUTPUT_FILENAME}")