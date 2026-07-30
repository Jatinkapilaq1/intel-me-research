# Social Media Posts

---

## LINKEDIN POST

I asked my Intel laptop's hidden second computer who it is. It answered.

Every modern Intel laptop has a secret processor running inside it — the Management Engine. It operates 24/7 with its own OS, network stack, and encrypted filesystem. Intel's tools to talk to it are locked behind NDAs.

So I built my own.

One Python script, zero dependencies. It connects to the ME through the HECI interface and asks questions:

- "What's your version?" → MKHI v3.1
- "Show me your parts list" → 8 internal partitions decoded
- "What's at this address?" → A different value every time (memory leak)

7 out of 12 MKHI commands responded. The ME is alive, talking, and leaking runtime memory.

No NDAs. No corporate tools. Just Python and curiosity.

Full tool + code: https://github.com/Jatinkapilaq1/intel-me-research
Presentation: https://jatinkapilaq1.github.io/intel-me-research/evidence/PRESENTATION.html

#HECISpy #InfoSec #ReverseEngineering #IntelME #CyberSecurity

---

## TWITTER/X THREAD

1/4 Your Intel laptop has a secret second computer inside it.
It runs 24/7. Has its own OS, network, and encrypted storage. No antivirus can see it.
I wrote a Python script that talks to it directly.

2/4 First question: "Who are you?"
Response: MKHI v3.1
Next: "Show me your parts list"
Response: 8 partitions — FTPR, RBEP, PMCP, IOMP, NPHY, TBTP, PCHC, OEMP
All with versions, encryption status, and Intel's signature.

3/4 Then I found something weird.
GEN.1B returns a value that CHANGES every time I ask.
Upper bits stay constant (base address). Lower bits change (runtime data).
This is a memory leak through a factory protocol.

4/4 Full tool + writeup:
https://github.com/Jatinkapilaq1/intel-me-research
One command to run: python heci_spy.py
Try it yourself. Share with #HECISpy

---

## REDDIT POST (r/netsec)

Title: I reverse-engineered Intel's HECI protocol and built a Python tool that talks to the ME directly

Body: Every Intel laptop has a Management Engine — a hidden coprocessor that runs independently of the CPU. It has its own OS (ARC EM), network stack, and encrypted filesystem. Intel's official tools are locked behind NDAs.

I reverse-engineered the HECI/MKHI protocol from the Windows driver and built a zero-dependency Python script that connects to the ME directly.

What I found:
- MKHI v3.1 confirmed (first public doc on CSME 16.x)
- 8 internal partitions with versions + encryption status
- GEN.1B leaks a dynamic memory value that changes every run
- SPI flash is completely blocked (all read/write/erase hang)
- Only MKHI client available (no AMT, no ICC on consumer SKU)

Tool: https://github.com/Jatinkapilaq1/intel-me-research
Just run: python heci_spy.py (Windows admin required)
Report saves automatically with #HECISpy

---

## YOUTUBE SHORTS DESCRIPTION

Your Intel laptop has a secret second computer inside it. I wrote a Python script that talks to it directly.

MKHI v3.1 | FW 16.0.1735.15 | 8 secret partitions | Memory leak confirmed

Try it yourself:
https://github.com/Jatinkapilaq1/intel-me-research

#HECISpy #IntelME #CyberSecurity #ReverseEngineering
