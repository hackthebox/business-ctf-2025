#!/usr/bin/python3

from dtmf import detect
import soundfile as sf

data, sr = sf.read('dtmf_audio.wav')

tones = ""
sils = 0
for t in detect(data, sr):
    if t.tone == None:
        sils += 1

    if t.tone != None and sils > 5:
        tones += str(t.tone)
        sils = 0

print("Tones:", tones)
