## Unit 11 Homework: Network Security


### Bonus Lab: "Green Eggs & SPAM"
In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.
 
- You will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.
 
- As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.
 
- You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling **Threat Intelligence** as part of your incident report.

#### Threat Intelligence Card

**Note**: Log into the Security Onion VM and use the following **Indicator of Attack** to complete this portion of the homework. 

Locate the following Indicator of Attack in Sguil based off of the following:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

Answer the following:

1. What was the indicator of an attack?
   - Hint: What do the details of the reveal? 

    Answer: "What do the details of the ___ reveal?"
	This poorly written question is a bit difficult to answer, but I shall try.
	There are several indicators of attack.  The most serious is the attempt to download a .exe file.  This is almost always a suspicious action.


2. What was the adversarial motivation (purpose of attack)?

    Answer: The purpose of this attack was to download malware onto the device, most likely ransomeware.
	Source: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=JS/Nemucod

3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.

| TTP | Example | Findings |
| --- | --- | --- | 
| **Reconnaissance** |  How did they attacker locate the victim? | Unknown, likely a random phishing attempt.  
| **Weaponization** |  What was it that was downloaded?| A file called "40.exe"
| **Delivery** |    How was it downloaded?| The user downloaded this file from the internet using the Mozilla 4.0 web browser.  
| **Exploitation** |  What does the exploit do?| This exploit encrypts files on the target machine and holds them for ransom.  
| **Installation** | How is the exploit installed?| It is downloaded from the internet and then the incautious user attempts to open the file, which sets the process in motion.    
| **Command & Control (C2)** | How does the attacker gain control of the remote machine?| The malware copies itself into several folders, installs new files in the %APPDATA% folder, and modifies registry entries tso that it runs each time the device is started.
| **Actions on Objectives** | What does the software that the attacker sent do to complete its tasks?| The installed ransomeware searches through all folders for a variety of files (from .3fr to .ztmp) and encrypts them.  
																									   Links are provided to "decryption" sites (paid for with bitcoin, naturally) and shadow files are deleted in order to prevent restoration from a local backup.  
	Source: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32%2fTescrypt

4. What are your recommended mitigation strategies?

    Answer: Train users to avoid phishing attempts, do not download suspicious files, set up accounts so that malware cannot easily achieve root access or change registry entries, run regular anti-virus scans and quarantine suspicious files.

5. List your third-party references.

    Answer: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=JS/Nemucod
			https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32%2fTescrypt
			https://www.upguard.com/blog/what-are-indicators-of-attack

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
