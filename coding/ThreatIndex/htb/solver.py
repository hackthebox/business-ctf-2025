#!/usr/bin/env python3

KEYWORD_WEIGHTS = {
  "scan": 1,
  "response": 2,
  "control": 3,
  "callback": 4,
  "implant": 5,
  "zombie": 6,
  "trigger": 7,
  "infected": 8,
  "compromise": 9,
  "inject": 10,
  "execute": 11,
  "deploy": 12,
  "malware": 13,
  "exploit": 14,
  "payload": 15,
  "backdoor": 16,
  "zeroday": 17,
  "botnet": 18,
}

data = input()
ans = 0
for keyword, weight in KEYWORD_WEIGHTS.items():
  ans += data.count(keyword) * weight
print(ans)