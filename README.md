# Introduction-to-Ethical-Hacking

## Information Security Overview

### 1️⃣ Elements of Information Security
Information security is about protecting information from unauthorized access, use, disclosure, disruption, modification, or destruction. Its core elements are often called **CIA Triad:**

  **1. Confidentiality:** Ensures that only authorized people can access the information.

  **2. Integrity:** Ensures that data remains unchanged or should not be alterd unless authorized.

  **3. Availability:** Ensures that data should be available when needed.

### 2️⃣ Classification of attacks

  - **Source**
    - **External attack:** From outside the organization (e.g., random hacker)
    - **Internal attack:** From someone inside the organization (e.g., disgruntled employee)

- **Nature**
  - **Passive attacks:** Attacker only monitors or intercepts data (e.g., eavesdropping, traffic sniffing)
  - **Active attacks:** Attacker modifies, deletes, or injects data (e.g., malware, ransomware)

- **Target**
  - **Network attacks:** DDoS, packet sniffing
  - **Host attacks:** Malware infection, privilege escalation
  - **Application attacks:** SQL injection, XSS

- **Motivation**
  - Financial, political, personal, or just testing skills (script kiddies)

### 3️⃣ Information Warfare

  - Using **Information Technology as a weapon** to attack or influence an adversary.
  - **Examples:**
    - **Cyber Espionage:** Stealing secrets (e.g., APTs targeting government agencies).
    - **Propaganda / Psychological Warfare:** Spreading fake news to influence elections.
    - **Disruption:** Taking down power grids and communication networks.

### ✅ Key Takeaways

- **Information security** = Protecting Confidentiality, Integrity, Availability.
- Attackers are classified by **source, nature, target and motivation.**
- **Information Warfare** is large-scale cyber operations often used by governments or cybercriminals.

---

## Hacking Concepts

### 1️⃣ What is Hacking?

- **Definition:** Act of identifying and exploiting weaknesses in computers, networks, or applications to gain unauthorized access or perform unintended actions.
- **Key point:** Hacking iyself is **not always illegal**. It depends on intent.(malicious vs ethical)
- **Example:**
  - Malicious hacker breaking into a bank system to steal money.
  - Security researcher testing a company’s website for vulnerabilities (with permission).

### 2️⃣ Who is a Hacker?

- A hacker is a skilled individual who uses technical knowledge to **solve problems or exploit weaknesses** in a system.
- **Types of hackers:**
  - **White hat (Ethical Hackers):** Authorized professionals who test and secure systems.
  - **Black Hat (Criminal Hackers):** Malicious hackers who exploit systems for personal gain.
  - **Grey Hat:** Hackers who sometimes break laws but without malicious intent (e.g., reporting a vulnerability without permission).
  - **Script Kiddies:** Beginners using pre-made hacking tools without deep knowledge.
  - **Hacktivists:** Hackers motivated by political/ideological causes.
  - **State-Sponsored Hackers:** Government-backed hackers conducting espionage or cyber warfare.

### ✅ Key Takeaway:

- Hacking = finding and exploiting vulnerabilities.
- Hackers can be good (white hat), bad (black hat), or somewhere in between.

---

## Ethical Hacking Concepts

### 1️⃣ What is Ethical Hacking?

- **Definition:** Ethical hacking is the authorized practice of bypassing system security to identify vulnerabilities before malicious hackers exploit them.
- **Key Idea:** It’s legal hacking performed with permission.

### 2️⃣ Why Ethical Hacking is Necessary

- Helps organizations **find and fix vulnerabilities** before attackers do.
- Ensures **data protection** for customers and businesses.
- Prevents **financial loss** from cyber attacks.
- Builds **trust and compliance** with laws like GDPR, HIPAA, PCI DSS.

### 3️⃣ Scope and Limitations of Ethical Hacking

- **Scope:**
  - Vulnerability assessment
  - Penetration testing
  - Network and web app testing
  - Cloud security testing

- **Limitations:**
  - Requires **legal authorization** (can’t hack without permission).
  - Access is often limited to **scope defined by client.**
  - Cannot guarantee **100% security**—new threats appear constantly.

### 4️⃣ AI-Driven Ethical Hacking

- **Definition:** Using artificial intelligence (AI) and machine learning (ML) to **enhance security testing** and detect vulnerabilities.
- **Examples:**
  - AI tools scanning millions of lines of code for flaws.
  - Machine learning detecting unusual network behavior.

### 5️⃣ How AI-Driven Ethical Hacking Helps Ethical Hackers?

- Automates repetitive tasks (e.g., vulnerability scanning).
- Detects **zero-day exploits** faster with anomaly detection.
- Analyzes **large datasets/logs** quickly.
- Enhances **threat intelligence** and prediction of attacks.

### 6️⃣ Myth: AI will Replace Ethical Hackers

- **Reality:** AI can assist, but human creativity, intuition, and problem-solving are irreplaceable.
- Hackers constantly invent new attack methods that AI cannot fully predict.
- Ethical hackers + AI = **stronger defense.**

### 7️⃣ ChatGPT-Powered AI Tools for Ethical Hackers

- **Use Cases:**
  - Generating payloads or scripts (legally, in labs).
  - Explaining vulnerabilities and suggesting mitigations.
  - Assisting in report writing and documentation.
  - Simulating phishing or social engineering scenarios (safely).
- **Note:** Should be used responsibly and ethically, not for malicious activity.

### ✅ Key Takeaway:

Ethical hacking is legal hacking with permission to strengthen security. While AI is becoming a powerful assistant in cybersecurity, human ethical hackers remain essential for creativity, adaptability, and strategic defense.

---

## Hacking Methodologies and Frameworks

### 1️⃣ CEH Ethical Hacking Framework

- A **structured process** followed by ethical hackers to simulate real-world attacks and identify vulnerabilities.
- **Phases:**

  **1. Reconnaissance (Footprinting):** Gathering info about the target (e.g., open ports, domains).
  **2. Scanning:** Using tools (Nmap, Nessus) to discover live systems and services.
  **3. Gaining Access:** Exploiting vulnerabilities to enter the system.
  **4. Maintaining Access:** Installing backdoors or persistence to simulate attacker behavior.
  **5. Clearing Tracks:** Erasing logs or hiding activity (for simulation).
  **6. Reporting:** Documenting findings and mitigation steps.

### 2️⃣ Cyber Kill Chain Methodology

Developed by Lockheed Martin, it models the stages of a cyber attack.

- **Stages:**

  **1. Reconnaissance:** Researching the target.
  **2. Weaponization:** Creating malware or exploit payload.
  **3. Delivery:** Sending the exploit (email, USB, phishing link).
  **4. Exploitation:** Executing malicious code.
  **5. Installation:** Installing malware/backdoor.
  **6. Command & Control (C2):** Attacker establishes remote control.
  **7. Actions on Objectives:** Final goal (data theft, destruction, espionage).

### Tactics, Techniques, and Procedures (TTPs)

- **Tactics:** The high-level goals (e.g., steal data, disrupt service).
- **Techniques:** The methods (e.g., phishing, SQL injection).
- **Procedures:** Step-by-step execution (craft phishing email → send → capture credentials).

### 3️⃣ Adversary Behavioral Identification

- Focuses on **identifying patterns of attacker behavior** instead of just specific malware.
- **Example:** Detecting repeated login attempts from unusual locations.
- Helps defenders spot **persistent threats** (APTs).

### 4️⃣ Indicators of Compromise (IoCs)

- **Definition:** Forensic clues that indicate a system **may be compromised.**
- **Examples:**
  - Unusual outbound traffic
  - Unknown processes running
  - Suspicious registry changes
  - Unexpected system reboots

 ### 5️⃣ Categories of Indicators of Compromise

 - **File-based IoCs:** Malicious files, unusual hash values.
 - **Network-based IoCs:** Suspicious IPs, abnormal traffic patterns.
 - **Host-based IoCs:** Unusual processes, log entries, registry edits.
 - **Email-based IoCs:** Phishing attachments, spoofed email headers.

### 6️⃣ MITRE ATT&CK Framework

- A globally used **knowledge base of adversary TTPs.**
- Organized into **Tactics (objectives)** and **Techniques (methods)**.
- Example:
  - **Tactic:** Credential Access
  - **Technique:** Brute Force, Keylogging
- Widely used by security teams for **threat detection, defense strategies,** and **red teaming**.

### 7️⃣ Diamond Model of Intrusion Analysis

- A framework for analyzing cyber intrusions with **four core features:**
  
  **1. Adversary:** The attacker.
  
  **2. Infrastructure:** Tools, servers, domains used by the attacker.
  
  **3. Capability:** Malware, exploits, techniques.
  
  **4. Victim:** Target organization or individual.
- Helps analysts connect attacker activity, tools, and victim details into one picture.

### ✅ Key Takeaway:

- Frameworks like **CEH, Cyber Kill Chain, MITRE ATT&CK, and Diamond Model** provide structured ways to **understand, simulate, and defend** against attacks.
- Ethical hackers use these models to think like attackers and help organizations strengthen defenses.

---

## Information Security Controls

### 1️⃣ Information Assurance (IA)

- **Definition:** Ensuring that information is confidential, integral, and available (CIA triad) to authorized users.
- **Focus:** Protect data from unauthorized access, tampering, or loss.
- **Example:** Bank systems ensuring customer data is encrypted, consistent, and always available online.

### 2️⃣ Continual/Adaptive Security Strategy

- Security is **not one-time**; it must **adapt to new threats**.
- Involves monitoring, updating security policies, and patching vulnerabilities continuously.
- **Example:** Automatic updates on web servers, AI-based monitoring of network traffic.

### 3️⃣ Defense-in-Depth

- **Layered security approach:** multiple defenses at different levels.
- Layers can include:
  - Firewalls (network)
  - Anti-malware (endpoint)
  - Multi-factor authentication (user access)
  - Encryption (data protection)

- **Example:** Even if a hacker bypasses a firewall, endpoint security and encryption protect the data.

### 4️⃣ What is Risk?

- **Definition:** The possibility that a threat exploits a vulnerability, causing harm.
- Formula (simplified):
```
Risk = Threat × Vulnerability × Impact
```
- **Example:** A server running outdated software is vulnerable; a hacker exploits it → potential financial loss.

### 5️⃣ Risk Management

- Process to **identify, evaluate, and mitigate risks**.
- Steps:
  1. Identify assets and threats
  2. Assess vulnerabilities
  3. Determine likelihood and impact
  4. Apply countermeasures
  5. Monitor & review

- **Example:** Patching software, applying firewalls, backup plans, disaster recovery.

### 6️⃣ Cyber Threat Intelligence (CTI)

- **Definition:** Information about cyber threats used to defend proactively.
- Includes data on attacker tactics, malware signatures, vulnerabilities, etc.
- **Example:** Security team receives CTI reports on new ransomware targeting Windows servers.

### 7️⃣ Threat Intelligence Lifecycle

**1. Planning & Direction:** Define what threats to monitor.

**2. Collection:** Gather raw threat data (logs, open sources, feeds).

**3. Processing:** Organize and filter data.

**4. Analysis:** Identify patterns, TTPs (tactics, techniques, procedures).

**5. Dissemination:** Share actionable intelligence with stakeholders.

**6. Feedback:** Review and improve intelligence.

### 8️⃣ Threat Modeling

- **Definition:** Visualizing potential threats to identify vulnerabilities before attacks happen.
- Tools: STRIDE, PASTA, attack trees.
- **Example:** Map your web app → identify SQL injection, XSS → prioritize fixes.

### 9️⃣ Incident Management

- **Definition:** Policies and procedures to **detect, report, and respond** to security incidents.
- **Example:** Security team monitors logs, detects unauthorized access, and alerts admin.

### 1️⃣0️⃣ Incident Handling and Response

- **Steps (IR process):**
  
  **1. Preparation** → Tools, access, playbooks ready

  **2. Identification** → Detect the incident

  **3. Containment** → Stop spread of attack

  **4. Eradication** → Remove malware or vulnerabilities

  **5. Recovery** → Restore systems safely

  **6. Lessons Learned** → Improve defenses

- **Example:** Responding to a ransomware attack by isolating infected machines, restoring backups.

### 1️⃣1️⃣ Role of AI and ML in Cybersecurity

- AI/ML helps analyze huge datasets quickly, detect anomalies, and predict attacks.
- Tasks AI/ML can help with:
  - Intrusion detection
  - Malware detection
  - Network traffic anomaly detection
  - Threat intelligence analysis

### 1️⃣2️⃣ How AI and ML Prevent Cyber Attacks

- **Real-time monitoring:** AI detects unusual login patterns or data transfers.
- **Predictive defense:** ML predicts potential vulnerabilities before exploitation.
- **Automation:** AI automates routine security tasks (e.g., patching, alerts).
- **Example:** A system using ML flags multiple failed login attempts from unusual countries → triggers MFA challenge or blocks IP.

### ✅ Key Takeaway:

Information Security Controls ensure **proactive and layered defense**. Risk management, threat intelligence, incident response, and AI/ML integration help organizations **stay ahead of attackers** instead of just reacting after damage.

--- 

## Information Security Laws and Standards

### 1️⃣ Payment Card Industry Data Security Standard (PCI DSS)

- **Purpose:** Protect cardholder data and prevent fraud in payment systems.
- **Requirements:** Secure network, encrypt data, maintain access control, monitor and test systems.
- **Example:** Online stores must encrypt credit card information and regularly test firewalls.

### 2️⃣ ISO/IEC Standards

- **Purpose:** International standards for information security management.
- **Key standard:** ISO/IEC 27001 → framework for creating an Information Security Management System (ISMS).
- **Example:** Companies follow ISO 27001 to systematically manage and protect sensitive data.

### 3️⃣ Health Insurance Portability and Accountability Act (HIPAA)

- **Purpose:** Protect sensitive patient health information in the U.S.
- **Rules:** Privacy rule, security rule, breach notification.
- **Example:** Hospitals must encrypt electronic health records and restrict access to authorized personnel.

### 4️⃣ Sarbanes-Oxley Act (SOX)

- **Purpose:** Ensure financial reporting accuracy and prevent corporate fraud (mainly in U.S. public companies).
- **Requirement:** Proper internal controls and auditing of IT systems storing financial data.
- **Example:** Banks maintaining logs and backups for all transactions to comply with SOX audits.

### 5️⃣ Digital Millennium Copyright Act (DMCA)

- **Purpose:** Protect copyrighted material online and regulate digital content use.
- **Example:** You can’t illegally distribute software, movies, or music online; websites must respond to takedown requests.

### 6️⃣ Federal Information Security Management Act (FISMA)

- **Purpose:** Requires U.S. federal agencies to develop, document, and implement information security programs.
- **Example:** Government agencies must follow structured risk management and periodic security audits.

### 7️⃣ General Data Protection Regulation (GDPR)

- **Purpose:** Protect personal data of EU citizens.
- **Key rights:** Consent, right to access, right to be forgotten, data portability.
- **Example:** Websites collecting EU user data must explicitly ask for consent and allow data deletion on request.

### 8️⃣ Data Protection Act 2018 (DPA)

- **Purpose:** UK law aligning with GDPR to regulate personal data processing.
- **Example:** Companies in the UK must maintain records of how they handle personal data and report breaches within 72 hours.

### 9️⃣ Cyber Law in Different Countries

- **Purpose:** Each country has laws regulating cybercrime, data privacy, and online content.
- **Examples:**
  - **India:** IT Act 2000 (amended) → cybercrime and digital signatures.
  - **U.S.:** CFAA (Computer Fraud and Abuse Act) → hacking and unauthorized access.

### ✅ Key Takeaway:

Information Security Laws and Standards **ensure legal compliance, protect data, and guide organizations** in implementing secure practices. Ethical hackers and security professionals must understand these regulations to **avoid legal issues** while performing assessments.

---



# Footprinting-and-Reconnaissance

## 🔎 Footprinting Concepts

### 1. Reconnaissance (What it Means)

- **Reconnaissance** = Information gathering phase of hacking (legal or illegal).
- Before attacking, a hacker (or ethical hacker) collects as much data as possible about the target:

  - People (employees, emails, social media)
  - Technology (IP addresses, domains, servers, operating systems)
  - Security (firewalls, VPN, IDS/IPS, etc.)

**👉 Real-world analogy:**
Imagine you want to rob a bank (black-hat) or test security of a bank (ethical hacker).

- First, you observe: number of guards, cameras, entry/exit points.
- You don’t attack yet, you’re just gathering intel.

This is what Reconnaissance is in hacking.

### 2. Types of Footprinting/Reconnaissance

There are two main categories:

🔹 **Passive Footprinting**

    Collecting information without directly interacting with the target system.

- **Example:** Google search, LinkedIn employee details, Whois lookup, social media analysis.
- Safer because the target won’t know you’re investigating.

👉 Example: You Google site:example.com confidential and find exposed documents.

🔹 Active Footprinting

    Directly interacting with the target system to get information.

- **Example:** Port scanning (Nmap), pinging servers, banner grabbing.
- More risky because it may trigger IDS/IPS alerts.

👉 Example: Running nmap -sV example.com to see what services are running.

### 3. Information Obtained in Footprinting

During footprinting, you may gather:

  - **Network information:** IP addresses, subnets, domains.
  - **System information:** OS version, server software (Apache, IIS, Nginx).
  - **Employee information:** emails, phone numbers, social engineering targets.
  - **Security posture:** firewalls, VPN, IDS/IPS, cloud usage.
  - **Physical information:** office location, Wi-Fi SSIDs.

👉 **Real-world Example:** Suppose you’re hired to test security of abc.com.

  - Whois lookup gives you registrant name and DNS servers.
  - Google search reveals Excel files with employee emails.
  - Nmap shows port 3306 (MySQL) is open.
  - Now you know: employees + technology stack + possible entry points.

### 4. Objectives of Footprinting

Why footprinting is done?

  - **Understand Target** – Know the business, infrastructure, and attack surface.
  - **Identify Vulnerabilities** – Example: Outdated Apache version.
  - **Find Weak Links** – Example: An employee email that can be phished.
  - **Prepare for Exploitation** – Create attack strategies.

👉 **Example:** If you find that a company uses WordPress 4.7, you can later check for vulnerabilities in that version.

### 5. Footprinting Threats

Why is footprinting dangerous if done by attackers?

  - **Information leakage:** Sensitive data exposed online.
  - **Social engineering attacks:** Attackers may impersonate employees.
  - **Phishing attacks:** Emails harvested can be used for phishing.
  - **System compromise:** Publicly known vulnerabilities exploited.
  - **Physical threats:** Office address can lead to physical attacks.

👉 **Example:** A hacker finds employee details on LinkedIn and sends a phishing email pretending to be HR.

### 6. Footprinting Methodology

The step-by-step process ethical hackers follow:

1. **Define the target:**
   - Example: example.com
2. **Information Gathering (Passive)**
   - Whois lookup, DNS records, Google dorks, job postings.
3. **Network Enumeration (Active)**
   - Ping sweep, traceroute, Nmap scanning.
4. **Identify Technologies**
   - Find OS, web server, database, CMS, cloud provider.
5. **Gather Employee/Organizational Info**
   - Emails, phone numbers, social media accounts.
6. **Analyze and Document**
   - Create a footprinting report to plan next steps.

👉 **Example Flow:**
- Target: abc.com
- Whois → Find IP range 192.168.61.0/24.
- Google dorks → Found an Excel file with usernames.
- Nmap → Discovered SSH and MySQL open.
- Social media → Found sysadmin email.

---

## 🌐 Footprinting through Search Engines

Search engines (Google, Bing, DuckDuckGo, etc.) are powerful tools for **hackers and ethical hackers** to gather information. They index **publicly available data**, but often reveal sensitive or misconfigured data unintentionally exposed.

### 1. Footprinting Using Advanced Google Hacking Techniques

Google allows special search operators (called Google Dorks) to refine searches.
Hackers use these operators to find hidden files, misconfigurations, or sensitive information.

Common Google Dorks:

  - ```site:example.com``` → Shows indexed pages only from example.com.
  - ```filetype:pdf confidential``` → Finds confidential PDFs.
  - ```intitle:"index of"``` → Finds exposed directories.
  - ```inurl:admin``` → Finds login/admin panels.

👉 **Real-World Example:** Searching filetype:xls site:abc.com may reveal spreadsheets with employee data.

### 2. What Can a Hacker Do with Google Hacking?

- Using Google Hacking, attackers can:

  - Find login pages (inurl:login)
  - Discover config files (filetype:cfg)
  - Identify error messages revealing server info
  - Locate database dumps (filetype:sql)
  - Access exposed cameras (inurl:/view.shtml)

👉 **Case Study:** A hacker once found NASA login portals using inurl:wp-login.php site:nasa.gov.

### 3. Footprinting Using Advanced Google Hacking Techniques with AI

- AI can automate Google Dorking by:
  - Generating custom dork queries based on target domain.
  - Filtering useful results vs noise.
  - Summarizing sensitive findings.

👉 **Example:** Instead of manually typing 50 queries, an AI-powered script can run site:abc.com filetype:pdf, site:abc.com intitle:"index of", etc., and return a list of sensitive URLs.

### 4. Google Hacking Database (GHDB)

- GHDB is a repository of pre-built Google Dorks maintained by security researchers.
- Website: https://www.exploit-db.com/google-hacking-database
- Categories include:
  - Files with passwords
  - Vulnerable servers
  - Sensitive directories
  - Error messages

👉 **Example:**
From GHDB, you can find a dork like:
intitle:"Index of /" password → which shows password files in public folders.

### 5. VPN Footprinting through Google Hacking Database

- Attackers can also identify VPN login portals exposed online.
- Common Dorks:

  - inurl:/remote/login (Fortinet VPN)
  - intitle:"GlobalProtect Portal" (Palo Alto VPN)
  - inurl:logon.html (Citrix VPN)

👉 **Example:** Using GHDB, a hacker may find a misconfigured Cisco VPN portal that reveals version details.

### 6. VPN Footprinting through Google Hacking Database with AI

- AI can enhance VPN footprinting by:

  - Automatically identifying if the VPN version is outdated.
  - Matching it with known CVEs (Common Vulnerabilities & Exposures).
  - Generating possible exploitation paths.

👉 **Example:** AI detects a Fortinet VPN login page and checks if it matches a known vulnerability (like CVE-2018-13379, a famous Fortinet SSL VPN bug).

### 7. Footprinting through SHODAN Search Engine

Shodan.io
 = “Google for Hackers.”

- Unlike Google (which indexes websites), Shodan indexes devices connected to the internet.
- You can find:

  - Exposed webcams
  - IoT devices (smart homes, routers, printers)
  - VPNs, firewalls, databases
  - Servers with specific ports/services

👉 **Example:** Searching Shodan for port:3389 shows exposed RDP servers (Remote Desktop).

### 8. Other Techniques for Footprinting through Search Engines

- Apart from Google & Shodan:

  - **Bing Dorking** – Similar operators to Google.
  - **DuckDuckGo Search** – Sometimes shows data Google misses.
  - **Censys.io** – Another tool like Shodan for device scanning.
  - **ZoomEye** – Chinese equivalent of Shodan.

👉 **Example:** Searching on Censys may reveal SSL certificates of a target company, helping enumerate subdomains.

---

## 🌍 Footprinting through Internet Research Services

Internet research services are publicly available online resources that attackers or ethical hackers use to gather deeper information about a target beyond search engines. This is part of OSINT (Open Source Intelligence).

### 1. Finding a Company’s Top-Level Domains (TLDs) and Sub-domains

- **TLDs** = extensions like .com, .org, .net, .in.
- Companies often own multiple TLDs (e.g., google.com, google.in, google.org).
- **Subdomains** = subdivisions of the main domain (e.g., mail.google.com, dev.google.com).

How hackers find them:

- Tools: sublist3r, Amass, crt.sh, dnsdumpster.com.
- Passive way: Check SSL certificates → they often list subdomains.

👉 **Example:** A company has portal.abc.com for internal logins, which might be overlooked by admins but indexed online.

### 2. Finding TLDs and Sub-domains with AI

AI can:

- Automate subdomain enumeration with multiple tools (Sublist3r + Amass + crt.sh).
- Cross-check which subdomains are live.
- Match them with vulnerabilities in CVE databases.

👉 **Example**: AI finds vpn.abc.net and correlates it with an outdated version → potential entry point.

### 3. Extracting Website Information from Archive.org

- Archive.org (Wayback Machine) stores historical snapshots of websites.

- Hackers use it to find:

  - Old pages containing sensitive info.
  - Deprecated APIs/endpoints.
  - Exposed employee details (before they were removed).

👉 **Example:** abc.com may have hidden admin pages today, but in 2016 snapshots you find /admin/login.php.

### 4. Footprinting through People Search Services

- Websites like Pipl, Spokeo, PeekYou, BeenVerified provide personal data.
- Attackers can collect: phone numbers, emails, social media profiles, addresses.
- Used for social engineering attacks (phishing, impersonation).

👉 Example: Searching for an employee’s name reveals LinkedIn + GitHub → attacker learns about technologies the company uses.

### 5. Footprinting through Job Sites

- Job postings often leak internal details:
  - Technologies used (e.g., “looking for AWS & Kubernetes admin”).
  - Security tools (“must have Splunk experience”).
  - Infrastructure scale.

👉 **Example:** If abc.com posts a job for “Oracle DBA with SQL*Plus experience,” an attacker knows Oracle DB is in use.

### 6. Dark Web Footprinting

The **Dark Web** is used by attackers to buy/sell data.
- Hackers search for leaked credentials, company documents, or data dumps.
- Tools: Tor Browser, marketplaces, breach databases.

👉 **Example:** An attacker finds abc.com employee emails + passwords leaked from a previous breach.

### 7. Searching the Dark Web with Advanced Search Parameters

- Dark Web search engines (e.g., Ahmia, Onion Search Engine) allow specific queries.
- Example parameters:
    - ```company.com password```
    - ```company.com confidential```

👉 **Case:** A security researcher found banking credentials of employees from a past leak indexed on a hidden forum.

### 8. Determining the Operating System

Footprinting can also reveal a company’s OS:
  - Job postings (“Linux Admin required”).
  - Shodan scan showing Windows RDP ports open.
  - Banner grabbing from services.

👉 **Example:** If Nmap shows ```Microsoft-IIS/10.0```, attacker knows the server is **Windows Server 2016+.**

### 9. Competitive Intelligence Gathering

This means gathering business-related intelligence for hacking or analysis.

- **When Did the Company Begin? How Did it Develop?**
  → From Crunchbase, Wikipedia, company blogs.

- **What Are the Company's Plans?**
  → From press releases, news articles, job postings.

- **What Do Experts Say?**
  → From forums, tech blogs, analyst reports.

👉 **Example:** If a company announces it is “migrating to AWS Cloud,” attackers may target misconfigured S3 buckets.

## 10. Other Techniques for Footprinting through Internet Research Services

- Social bookmarking sites (Reddit, Quora, GitHub).
- Pastebin leaks (searching ```site:pastebin.com company.com```).
- SSL certificate transparency logs (crt.sh).
- Tech blogs where employees write about their work.

👉 **Example:** A developer posts a code snippet on GitHub that contains API keys.

---

## 👥 Footprinting through Social Networking Sites

Social media is one of the **richest sources of information** for hackers. Employees often **overshare** details about their company, technologies, or even internal systems without realizing attackers can use it.

### 1. People Search on Social Networking Sites

Attackers look up **employees, partners, or executives** on platforms like Facebook, Twitter, Instagram, LinkedIn, etc.

- Info gained:
  - Full name, job role, email ID pattern
  - Location, work culture, office pictures
  - Friends/colleagues (who can be social engineered)

👉 Example: Searching ```site:linkedin.com "Company ABC"``` on Google shows all employees working at ABC.

### 2. Gathering Information from LinkedIn

- LinkedIn is a goldmine for hackers because employees post:

  - Current role and responsibilities
  - Technologies they work with (“5 years of AWS, Docker, Kubernetes”)
  - Job switches (helps track who has insider knowledge)

👉 **Case Example:**
A sysadmin writes *“managing Fortinet firewalls and Splunk SIEM”*.
➡️ Now an attacker knows the company uses Fortinet + Splunk.

### 3. Harvesting Email Lists

- Attackers gather employee emails to use in **phishing or brute force attacks.**
- Common ways:
    - Guessing format: (```firstname.lastname@company.com```)
    - Scraping from LinkedIn, GitHub, or public documents.
    - Using tools like **theHarvester** or **Hunter.io**.

👉 **Example:** If one email is ```john.doe@abc.com```, then others likely follow the same pattern.

### 4. Harvesting Email Lists with AI

AI can:
- Predict email patterns (e.g., first.last, first_initial+last).
- Cross-verify emails with data leaks.
- Generate phishing targets list quickly.

👉 **Example:** AI scrapes 100 LinkedIn profiles from abc.com, detects the email format, and auto-builds a valid email list for spear phishing.

### 5. Analyzing Target Social Media Presence

Hackers analyze:

- Posting habits (when employees are active).
- Company events (conferences, new launches).
- Pictures/videos (sometimes show ID cards, desktops, whiteboards with passwords).
- Hashtags (#LifeAtABC, #TeamABC → reveals projects/office info).

👉 **Example:** An employee posts a picture of their workstation on Instagram → monitor shows internal dashboard URL.

### 6. Tools for Footprinting through Social Networking Sites

- **theHarvester** – Email/username gathering.
- **Maltego** – OSINT framework with social media integration.
- **Social-Searcher** – Monitors mentions across social media.
- **Creepy** – Finds geolocation info from Twitter/Flickr.
- **Sherlock** – Finds usernames across multiple platforms.

👉 **Example:** Using Sherlock, you find that a sysadmin’s username techguy21 is reused on GitHub → where he posted company code.

### 7. Footprinting through Social Networking Sites with AI

AI-powered footprinting helps by:
- Automating profile crawling.
- Extracting emails, job roles, and technologies from LinkedIn at scale.
- Detecting **patterns of behavior** (e.g., when employees log in or post).
- Analyzing images for hidden data (like EXIF metadata → location info).

👉 Example: AI scans employee selfies → metadata reveals GPS coordinates of the office → attacker now knows exact building location.

--- 

## 🌍 Whois Footprinting

Whois is one of the oldest and most useful methods for footprinting. It provides domain registration details stored in public records when someone buys a domain. Attackers (and ethical hackers) use it to find who owns a website, their contact details, and server information.

### 1. Whois Lookup

What it is:

- Whois lookup shows **domain registration info** from registrars like GoDaddy, Namecheap, etc.
- Data can include:

    - Registrant’s name/organization
    - Email address & phone number
    - Domain creation & expiry date
    - Nameservers (DNS servers)
    - Registrar details
 
**How hackers use it:**
- If the registrant uses **personal email**, attackers may try phishing.
- If the expiry date is near, attackers may try domain hijacking (re-registering it if it lapses).
- Nameservers reveal hosting provider (AWS, Cloudflare, etc.).

**Tools for Whois lookup:**
- Online tools: whois.domaintools.com, whois.com
- CLI:

  ```
  whois example.com
  ```

👉 **Example:**

- Looking up abc.com might reveal:
- Registrant: ABC Technologies Pvt Ltd
- Email: admin@abc.com
- Nameservers: ns1.aws.amazon.com, ns2.aws.amazon.com

➡️ Now you know the company uses AWS hosting.

### 2. Finding IP Geolocation Information

After Whois, hackers map **where the IP address is located physically.**

**What it reveals:**

- Country, city, ISP (Internet Service Provider).
- Hosting provider (AWS, Azure, Google Cloud, etc.).
- Sometimes even **exact data center region.**

**Why it matters:**

- Helps attackers know whether a site is hosted **on-premises or cloud.**
- Useful for **social engineering** (e.g., pretending to be local ISP support).
- Helps choose **attack timing** (timezone differences).

**Tools for IP Geolocation:**

- iplocation.net
- ipinfo.io
- Shodan.io (also provides geolocation + open ports).
- CLI (Linux):

  ```
  curl ipinfo.io/8.8.8.8
  ```
👉 **Example:** If IP 192.168.61.129 resolves to Bangalore, India → ISP: Reliance Jio, attackers know where the server is hosted.

---

## 🌐 DNS Footprinting

DNS (Domain Name System) is like the internet’s directory – it maps **domain names** (example.com) to **IP addresses**.
Footprinting DNS gives attackers technical insights into a company’s network.

### 1. Extracting DNS Information

Attackers gather DNS records to understand a target’s infrastructure.

**Important DNS Records:**

- **A Record** → Maps a domain to an IPv4 address.
  - ```abc.com → 203.0.113.10```

- **AAAA Record** → Maps to IPv6 address.
- **MX Record** → Mail server info.
  - If ```mail.abc.com``` points to Google → company uses Gmail/Google Workspace.

- **NS Record** → Nameservers (who handles DNS).
- **TXT Record** → Can reveal SPF/DKIM for email, sometimes API keys or misconfigurations.
- **CNAME Record** → Alias for subdomains.

**Tools to extract DNS info:**

- nslookup (Windows/Linux)
  ```
  nslookup abc.com
  ```

- dig (Linux/macOS)
  ```
  dig abc.com ANY
  ```

- Online: ```dnsdumpster.com```, ```MXToolBox```.

👉 Example:
Running dig abc.com MX might show →
```
mail.abc.com priority 10
```
➡️ Now attacker knows company’s mail server.

### 2. DNS Lookup with AI

AI can **automate DNS lookups** by:

- Querying multiple record types in one go.
- Identifying patterns (like naming conventions for subdomains).
- Correlating DNS info with known vulnerabilities.

👉 Example: AI checks ```vpn.abc.com``` → detects it points to ```Cisco ASA VPN``` → matches with a CVE like **CVE-2020-3452.**

Instead of manually testing every subdomain, AI automates scanning + vulnerability mapping.

### 3. Reverse DNS Lookup

**Forward DNS** → Domain → IP
**Reverse DNS** → IP → Domain

- Reverse DNS finds **all domains hosted on a specific IP.**
- Useful when one server hosts multiple websites (shared hosting).
- Can reveal **hidden/test domains** not publicly known.

**Tools:**
- Command line:
  ```
  nslookup 203.0.113.10
  ```

- Online: viewdns.info/reverseip

👉 **Example:**
IP ```203.0.113.10``` may resolve to:

- abc.com
- test.abc.com
- dev.abc.com

➡️ Now attacker knows additional subdomains like ```dev.abc.com``` which might be less secure.

---

## 🌐 Network and Email Footprinting

This step focuses on mapping **how data flows across the internet** (network-level reconnaissance) and learning how to extract information from **email communications.**

### 1. 🔎 Locate the Network Range

When targeting an organization, the attacker first needs to know **which IP range** (block of IP addresses) belongs to the target.

- Every organization has IP ranges assigned by Regional Internet Registries (RIRs) like ARIN, RIPE, APNIC.
- Using tools like ```whois```, attackers can find the **NetRange**.

**Example:**
```
whois microsoft.com
```
Might show:
```
NetRange:   13.64.0.0 - 13.107.255.255
OrgName:    Microsoft Corporation
```

👉 This means Microsoft owns 13.64.0.0 → 13.107.255.255.
An attacker now knows all live hosts will lie in this range.

**✅ Real-world use**: Security teams monitor their entire IP range for vulnerabilities, not just their main domain.

### 2. 🌍 Traceroute

Traceroute maps the path packets take from your computer to the target server.

- Shows **routers (hops) in between**.
- Reveals the **network infrastructure** (ISPs, routers, firewalls).
- Helps identify **where the target’s network begins**.

**Example:**
```
traceroute google.com    # Linux / Mac
tracert google.com       # Windows
```

You might see output like:

```
1  192.168.1.1 (home router)
2  isp.local.net
3  72.14.219.1 (Google edge router)
...
```

👉 From this, you know where the **internal Google network starts**.

### 3. 🤖 Traceroute with AI

Attackers (and defenders) can use AI models to analyze traceroute outputs and identify:

- Which hops belong to ISPs vs the target
- Possible VPNs, proxies, or CDN usage (like Cloudflare)
- Detect geographical routes → AI can map hops on a world map.

✅ **Example:** AI sees ```ae1.paris.gblx.net``` and automatically says “Hop passes through Paris, Global Crossing ISP”.

### 4. 📊 Traceroute Analysis

Key insights attackers/security analysts get:

- Where firewalls filter packets (e.g., sudden timeout at hop 6).
- Which ISPs partner with the target company.
- Latency points (helps in DoS attack planning).
- Detect load balancers/CDNs if multiple routes appear.

### 5. ⚙️ Traceroute Tools

- **Built-in**: ```tracert``` (Windows), ```traceroute``` (Linux/Mac).
- **VisualRoute** → GUI + Geo-mapping.
- **Path Analyzer Pro** → Advanced traceroute with reporting.
- **tracetcp** → Traceroute over TCP (can bypass ICMP block).

### 6. 📧 Tracking Email Communications

Email headers leak tons of information.
Attackers can trace:

- The **originating IP** of the sender.
- The **mail servers** used.
- Possible **geolocation**.

### 7. 📜 Collecting Information from Email Header

Let’s say you received this header:

```
Received: from mail.example.com (mail.example.com [203.0.113.25])
  by smtp.gmail.com with ESMTPS id x12si87332qtk.23.2025.08.31
```

- **203.0.113.25** = Mail server IP.
- Running ```whois 203.0.113.25``` shows the organization hosting it.
- Sometimes, the **sender’s real IP** leaks (if no anonymization).

**✅ Defenders:** Configure mail servers to remove sensitive info.

### 8. 🛠️ Email Tracking Tools

- **MXToolBox (mxtoolbox.com)** → Analyze mail headers, MX records.
- **PoliteMail / Yesware** → Track if mail is opened (legit marketing tools, abused by attackers).
- **Infoga** → OSINT tool for email footprinting.
- **Email Header Analyzer (Google Apps)** → Decodes headers into readable info.

---

## 🎭 Footprinting through Social Engineering

Social Engineering is the **art of manipulating people** into giving up confidential information rather than breaking systems technically.
It’s one of the **most effective footprinting techniques** because humans are the weakest security link.

### 1. Collecting Information through Social Engineering on Social Networking Sites

- Attackers exploit trust and oversharing on platforms like Facebook, Instagram, LinkedIn, or Twitter (X).
- People often reveal:

  - Birthdays, phone numbers, and emails
  - Workplace and job role details
  - Travel plans and geolocation tags
  - Family connections and personal interests

📌 Techniques:

- **Fake Profiles (Impersonation)**: Attacker creates a fake persona to connect with employees.
- **Phishing via Social Media:** Sending malicious links through DMs.
- **Information Harvesting:** Collecting info from public profiles, group memberships, or likes.

⚡ **Example:** An attacker connects with an employee on LinkedIn, poses as a recruiter, and extracts internal project details by casual chatting.

### 2. Collecting Information Using Eavesdropping, Shoulder Surfing, Dumpster Diving, and Impersonation

**🔍 Eavesdropping**

- Secretly listening to conversations in public (cafes, airports, offices).
- Attackers may **overhear credentials, project names, or phone calls**.

**👀 Shoulder Surfing**

- Looking over someone’s shoulder to **steal sensitive info**.
- **Example:** Watching someone type an ATM PIN, office password, or email login.

**🗑 Dumpster Diving**

- Searching through trash bins to retrieve **confidential papers, notes, invoices, or USB drives**.
- **Example:** An attacker finds discarded documents with network details.

**🎭 Impersonation**

- Pretending to be a **trusted individual** (IT staff, delivery person, or manager).
- **Example:** An attacker impersonates tech support, asks for Wi-Fi credentials under the pretense of fixing internet issues.

--- 

## 🤖 Footprinting Tasks using Advanced Tools and AI

Traditionally, footprinting relied on manual methods or limited automation.
But now, **AI + OSINT** (Open Source Intelligence) makes reconnaissance **faster, smarter, and harder to detect.**

### 1. AI-Powered OSINT Tools

AI-based OSINT tools can **analyze, correlate, and summarize massive amounts of public data** quickly.

**Popular AI-Powered Tools**

- **Maltego with AI plugins** → Visual link analysis of people, companies, domains. AI can automatically highlight suspicious connections.
- **SpiderFoot HX** → Automated OSINT scanner with AI to analyze results.
- **Recon-ng with AI Modules** → Automates domain, WHOIS, IP lookups with AI correlation.
- **Shodan AI Integrations** → AI analyzes IoT devices exposure trends.
- **ChatGPT / LLMs** → Can generate Google dorks, analyze traceroute output, summarize whois data, or correlate multiple OSINT sources.

**⚡ Example:**
Instead of manually checking 100 LinkedIn profiles, AI scrapes them, extracts job titles, and summarizes “Company X uses AWS, is hiring DevOps engineers, and recently shifted to Kubernetes.”

### 2. Create and Run Custom Python Script to Automate Footprinting Tasks with AI

You can build a Python script that:

- Collects OSINT (via APIs like Shodan, Whois, Google Dorks).
- Sends results to an AI model.
- AI summarizes & highlights the most **useful reconnaissance data.**

---




# Scanning-Networks

## Network Scanning Concepts 

### 1. Overview of Network Scanning

**👉 Definition:** Network scanning is the process of sending packets to a target network/system to identify:

- **Live hosts** (who is up and running?)
- **Open ports** (where can I knock?)
- **Services** (what’s listening on those ports?)
- **OS/versions** (what type of system am I dealing with?)

**⚡ Real-world analogy:** Imagine you’re a burglar (attacker) walking down a street of houses (network).

- Footprinting was you checking **which houses exist** in that street.
- Scanning is you walking up to each house and **knocking on every door/window** (ports) to see which ones respond.

**Types of Network Scanning**

**1. Ping Sweep** → To find live hosts. Example: ```ping -c 1 192.168.1.1```

**2. Port Scanning** → To check which ports are open. Example: ```nmap -p 1-1000 192.168.1.1```

**3. Service Scanning** → To identify what service/version runs on open ports. Example: **nmap -sV 192.168.1.1**

**4. OS Fingerprinting** → To guess the operating system. Example: ```nmap -O 192.168.1.1```

**⚠️ Why important?**

- Attackers use it for finding entry points.
- Defenders use it for hardening systems and detecting unauthorized scans.

### 2. TCP Communication Flags

**👉 Background:** TCP (Transmission Control Protocol) is connection-oriented. Before two computers talk, they must establish a connection using the **3-way handshake.**

**📌 TCP Flags**
Flags are tiny “switches” in TCP packets that control communication.

|   Flag   |      Name      |          Function          |       Example Use       |
|----------|----------------|----------------------------|-------------------------|
| **SYN**  | Synchronize    | Initiates a connection     | First step in handshake |
| **ACK**  | Acknowledgment | Confirms received data     | Step 2 & 3 in handshake |
| **FIN**  | Finish         | Politely ends a connection | “Goodbye” signal        |
| **RST**  | Reset          | Abruptly ends a connection | If port is closed       |
| **PSH**  | Push           | Sends data immediately     | Streaming/chat apps     |
| **URG**  | Urgent         | High-priority data         | 	Rare, used in VoIP     |

**⚡ TCP 3-way Handshake Example:**

1. Client → Server: **SYN** (Hey, I want to connect!)

2. Server → Client: **SYN+ACK** (Sure, let’s connect!)

3. Client → Server: **ACK** (Cool, we’re connected!)

✅ Connection established → Now data can flow.

**⚡ How Hackers Use Flags in Scanning**

Attackers manipulate flags to “trick” systems and detect open ports.

- **SYN Scan (nmap -sS)** → Half-open scan, stealthy, doesn’t complete handshake.
- **FIN Scan (nmap -sF)** → Sends FIN packet. Closed ports reply with RST, open ports stay silent.
- **NULL Scan (nmap -sN)** → Sends packet with no flags.
- **XMAS Scan (nmap -sX)** → Sends packet with FIN+PSH+URG.

**⚠️ Real-world use:**

- Security teams detect attackers if they see many SYN or XMAS packets in logs.
- Attackers use these scans because some firewalls respond differently → revealing information.

### 3. TCP/IP Communication

**👉 TCP/IP model** = the backbone of the internet.
It has 4 layers (simplified OSI model):

|       Layer         |  Example Protocols   |           Function           |
|---------------------|----------------------|------------------------------|
|   **Application**   | HTTP, FTP, SMTP, DNS | End-user interaction         | 
|    **Transport**    |       TCP, UDP       | Reliable/unreliable delivery | 
|    **Internet**     |       IP, ICMP       | Addressing & routing         |
| **Network Access**  |   Ethernet, Wi-Fi    | Physical transmission        | 

**TCP vs UDP**

- **TCP (Connection-oriented)** → Reliable (like WhatsApp double ticks). Uses handshake.

- **UDP (Connectionless)** → Fast but unreliable (like live streaming). No handshake.

**⚡ Example:**

- **TCP** → Banking apps (need reliability).
- **UDP** → Online games, VoIP (need speed).

**Real-world Example of TCP/IP in Scanning**

- Attacker sends a **SYN** to port 80 (HTTP).
- If server replies with **SYN+ACK**, port 80 is open → attacker can try exploits like SQLi on the web app.
- If server replies with **RST**, port is closed.
- If server ignores, firewall is blocking.

✅ That’s how tools like **Nmap, Masscan, ZMap** work under the hood.

### 🔑 Key Takeaways

- **Network scanning** = mapping active systems, ports, and services.
- **TCP flags** are manipulated by attackers for stealth scans.
- **TCP/IP model** explains how data moves across the internet.
- Understanding this is **critical** because every attack after scanning (exploitation, privilege escalation, etc.) depends on this knowledge.

---

## Scanning Tools

### 1. Nmap (Network Mapper)

**👉 Most popular network scanning tool.**

- Open-source, runs on Linux/Windows/Mac.
- Used for port scanning, service detection, OS fingerprinting, and scriptable scans (NSE).

**📌 Key Features:**

- **Host Discovery** → Find live systems.
- **Port Scanning** → Open, closed, filtered ports.
- **Service Version Detection** → e.g., Apache 2.4.29.
- **OS Fingerprinting** → Linux/Windows version guess.
- **NSE Scripts** → Automate tasks (brute force, vuln detection).

**⚡ Real-world Example:**

```
nmap -sS -sV -O 192.168.1.10
```

- ```-sS``` → SYN stealth scan
- ```-sV``` → Detect service version
- ```-O``` → OS fingerprinting

✅ Used daily by penetration testers and also by defenders to audit networks.

### 2. Hping3

👉 A **packet crafting tool** (command-line).

- Unlike Nmap (which automates scans), Hping3 gives **manual control** over TCP/IP packets.
- Good for **firewall testing, IDS evasion, and custom scans**.

**📌 Key Features:**

- Send TCP, UDP, ICMP packets with custom flags.
- Perform **traceroute** with different protocols.
- Test firewall rules and IDS detection.

**⚡ Example:** SYN flood (DoS test)

```
hping3 -S --flood -V -p 80 192.168.1.10
```

- Sends continuous SYN packets to port 80.
- Tests if server can handle SYN flood attacks.

### 3. Hping Scan with AI

👉 Modern use-case: Combine **AI automation** with Hping.

- AI can generate packet crafting scripts based on scanning goals.
- Example: Instead of manually setting flags, AI suggests the right combinations for stealth scans.

**⚡ Example:**

You ask AI → “Scan for open web ports stealthily”.

AI generates:
```
hping3 -S -p 80,443,8080 --scan 192.168.1.0/24
```

- Saves time and reduces human error.

✅ This is becoming popular in **red team automation.**

### 4. Metasploit Framework

👉 A **penetration testing platform** with built-in scanners.

- Mostly known for exploitation, but also has **auxiliary scanners.**
- Example: SMB scanner, SSH login brute force, port scanners.

**⚡ Example (inside Metasploit):**
```
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
run
```

- Scans all hosts in subnet for open TCP ports.

✅ Advantage → After scanning, you can immediately exploit vulnerable services within the same framework.

### 5. NetScanTools Pro

👉 A **Windows-based commercial toolkit** for network discovery.

- GUI-based (easy for beginners).
- Combines multiple tools: ping sweeps, traceroute, port scanning, SNMP scanning, etc.
- Good for corporate environments where GUIs are preferred over CLI.

**📌 Real-world Use:**

- Security analysts in enterprises use it for **documentation and quick discovery.**
- Less stealthy than Nmap/Hping3, but very useful for IT auditing.


### 🔑 Key Takeaways

- **Nmap** → Standard port/service/OS scanner.
- **Hping3** → Custom packet crafting for advanced scans.
- **Hping + AI** → AI-assisted packet scans for automation.
- **Metasploit** → Integrated scanning + exploitation.
- **NetScanTools Pro** → GUI-based scanning for corporate/Windows users.

---

## Host Discovery

### 1. Host Discovery Techniques

👉 Methods used to check if a system is **alive (up)** or **dead (down).**

- Can be **ICMP-based** (ping)
- Can be **TCP/UDP-based** (knocking on ports)
- Can be **Layer 2-based** (ARP scans inside LAN)

📌 Real-world use:

- Attackers → Save time by scanning only live hosts.
- Defenders → Detect unauthorized scans in logs.

### 2. ARP Ping Scan

👉 Works in **Local Area Network (LAN)** only.

- Sends ARP requests (```Who has 192.168.1.10?```)
- Live host replies with its **MAC address.**

**⚡ Example:**
```
nmap -PR 192.168.1.0/24
```

✅ Always works in LAN (because ARP cannot be blocked by firewalls).

### 3. UDP Ping Scan

👉 Sends UDP packets to a host.

- If ICMP Port Unreachable is received → Host is alive.
- If no reply → Could be firewalled or dropped.

**⚡ Example:**
```
nmap -PU 192.168.1.0/24
```

### 4. ICMP ECHO Ping Scan

👉 The classic ping (ICMP Echo Request).

- If host replies with ICMP Echo Reply → It’s alive.

**⚡ Example:**
```
nmap -PE 192.168.1.0/24
```

⚠️ Many networks block ICMP to prevent ping sweeps.

### 5. ICMP ECHO Ping Sweep

👉 Same as above, but scans multiple hosts in a subnet.

- Used to find all live systems quickly.

**⚡ Example:**
```
fping -a -g 192.168.1.0/24
```

### 6. ICMP Timestamp Ping Scan

👉 Sends an ICMP Timestamp request.

- If host responds → It’s alive (and gives system clock info).

**⚡ Example:**
```
nmap -PP 192.168.1.0/24
```

### 7. ICMP Address Mask Ping Scan

👉 Sends an ICMP Address Mask request.

- Host replies with its subnet mask.
- Rarely enabled today.

**⚡ Example:**
```
nmap -PM 192.168.1.0/24
```

### 8. TCP SYN Ping Scan

👉 Sends a SYN packet to a specific port (e.g., 80).

- If reply = **SYN+ACK** → Host is alive.
- If reply = **RST** → Host is alive but port closed.

**⚡ Example:**
```
nmap -PS80 192.168.1.0/24
```

### 9. TCP ACK Ping Scan

👉 Sends a TCP ACK packet to a port.

- If reply = **RST** → Host is alive.
- Useful to bypass firewalls that block SYN packets.

**⚡ Example:**
```
nmap -PA80 192.168.1.0/24
```

### 10. IP Protocol Ping Scan

👉 Sends packets using different IP protocols (ICMP, TCP, UDP, GRE, etc.).

- If any reply → Host is alive.

**⚡ Example:**
```
nmap -PO 192.168.1.0/24
```

### 11. Host Discovery with AI

👉 AI can automate host discovery by:

- Selecting best scan method depending on environment.
- Running parallel scans and adapting if blocked.
- Example: AI tries ICMP first, then switches to ARP if no response.

**⚡ Real-world use:**

- Red Teams → Faster stealth scans.
- Blue Teams → AI alerts when unusual ping patterns appear.

### 12. Ping Sweep Tools

📌 Tools to automate host discovery across a range of IPs:

- **Nmap** → ```nmap -sn 192.168.1.0/24```
- **fping** → Faster ICMP sweeps.
- **Angry IP Scanner (GUI)** → Beginner-friendly.
- **NetScanTools Pro** → Enterprise-grade.

### 🔑 Key Takeaways

- **ARP scans** → Best for LAN.
- **ICMP scans** → Classic but often blocked.
- **TCP/UDP scans** → Work when ICMP is blocked.
- **IP protocol scans** → Catch hosts behind firewalls.
- **AI + scanning tools** → Automates stealth & efficiency.

---

## Port and Service Discovery

### 1. Port Scanning Techniques

👉 Port = communication endpoint (like a door to a house).

- **Open port** → service is listening (e.g., port 80 = web server).
- **Closed port** → no service listening.
- **Filtered port** → firewall blocking.

**⚡ Tools:** Nmap, Masscan, Unicornscan, ZMap.

### 2. TCP Connect / Full-Open Scan

👉 Completes full TCP 3-way handshake.

- Reliable but noisy (easy to detect in logs).

**⚡ Example:**
```
nmap -sT 192.168.1.10
```

### 3. Stealth Scan (Half-Open Scan)

👉 Sends **SYN** → gets **SYN+ACK** → replies with **RST** (instead of ACK).

- Never completes handshake → stealthier.

**⚡ Example:**
```
nmap -sS 192.168.1.10
```

### 4. Inverse TCP Flag Scan

👉 Sends unusual flags (FIN, URG, PSH) to detect open ports.

- Closed ports → reply with **RST**.
- Open ports → no reply.

**⚡ Example:**
```
nmap -sN 192.168.1.10   # NULL scan (no flags)
nmap -sF 192.168.1.10   # FIN scan
nmap -sX 192.168.1.10   # Xmas scan
```

### 5. Xmas Scan

👉 Sends FIN + PSH + URG (like a Christmas tree 🎄 lit up).

- Same logic as inverse scans.

⚠️ Works best on Unix/Linux systems, Windows often ignores.

### 6. TCP Maimon Scan

👉 Sends **FIN/ACK** → some BSD-based systems misbehave.

- Detects open ports if no reply.

**⚡ Example:**
```
nmap -sM 192.168.1.10
```

### 7. ACK Flag Probe Scan

👉 Sends **ACK** packet.

- Used to check if firewall rules exist.
- If **RST** = port unfiltered, if no reply = filtered.

**⚡ Example:**
```
nmap -sA 192.168.1.10
```

### 8. IDLE/IPID Header Scan

👉 Uses a third-party zombie host to scan target.

- Super stealthy because traffic looks like it’s coming from the zombie, not you.

**⚡ Example:**
```
nmap -sI zombie_host 192.168.1.10
```

### 9. UDP Scan

👉 Sends UDP packets.

- If ICMP Port Unreachable → port closed.
- If no reply → open or filtered.

**⚡ Example:**
```
nmap -sU 192.168.1.10
```

⚠️ Slower than TCP scans.

### 10. SCTP INIT Scan

👉 **SCTP** = Stream Control Transmission Protocol (used in telecom).

- INIT packet used to check open SCTP ports.

**⚡ Example:**
```
nmap -sY 192.168.1.10
```

### 11. SCTP COOKIE ECHO Scan

👉 Sends **COOKIE-ECHO** instead of full INIT handshake.

- Stealthier SCTP scan.

**⚡ Example:**
```
nmap -sZ 192.168.1.10
```

### 12. SSDP and List Scan

- **SSDP Scan** → Finds devices using UPnP (IoT, smart TVs, routers).
- **List Scan (-sL)** → Doesn’t scan, just lists possible targets (DNS resolution check).

**⚡ Example:**
```
nmap -sL 192.168.1.0/24
```

### 13. IPv6 Scan

👉 Scanning IPv6 hosts (different from IPv4).

**⚡ Example:**
```
nmap -6 -sS 2001:db8::1
```

### 14. Port Scanning with AI

👉 AI helps by:

- Choosing stealthy scan methods automatically.
- Parallelizing scans and adapting if blocked.
- Automating post-scan analysis (e.g., “Port 3306 open → check MySQL vuln DB”).

**⚡ Example:** Ask AI → “Scan subnet for open databases” → It generates optimized Nmap/Hping scans.

### 15. Service Version Discovery

👉 Once ports are open, check service version.

- Example: Port 22 → SSH running OpenSSH 7.2p2.

**⚡ Example:**
```
nmap -sV 192.168.1.10
```

### 16. Service Version Discovery with AI

👉 AI can map detected versions to known CVEs automatically.

- Example: Detects Apache 2.4.49 → AI cross-checks → vulnerable to CVE-2021-41773.

### 17. Nmap Scan Time Reduction Techniques

👉 Large scans can be slow, so we use:

- ```-T4 / -T5``` → Faster timing.

- ```-max-retries``` → Limit retries.

- ```--min-rate``` → Packets per second.

- ```-Pn``` → Skip host discovery (assume hosts are up).

- ```-F``` → Fast scan (only common 100 ports).

**⚡ Example:**
```
nmap -sS -T4 -F 192.168.1.0/24
```

### 🔑 Key Takeaways

- **TCP/UDP scans** → Detect open/closed ports.

- **Stealth techniques (SYN, Xmas, IDLE)** → Avoid detection.

- **Service detection** → Know what’s running on those ports.

- **AI scanning** → Faster, smarter, less noisy.

- **Scan optimization** → Save time during big sweeps.


## 🌐 OS Discovery / Banner Grabbing (OS Fingerprinting)

### 1. OS Discovery / Banner Grabbing

**What it means:**

- Every system/service often reveals details about itself in its banner (text shown when you connect).
- **Example:** Connecting to an FTP or HTTP service may reveal OS + version.
- **Goal:** Extract this information to identify the target system’s operating system.

**Techniques:**

- **Active Banner Grabbing** → Send crafted requests to provoke banners.
- **Example:** ```telnet <ip> 21``` → FTP server may reply with 220 ProFTPD 1.3.5 (Debian).

- **Passive Banner Grabbing** → Capture traffic with Wireshark or tcpdump; infer OS info from banners without directly interacting.

### 2. How to Identify Target System OS

**Clues:**

- Service banners (Apache/2.4.29 on Ubuntu = Ubuntu Linux).
- Default ports/services (IIS = Windows, sshd = Linux/Unix).
- TTL values in packets:
    - Linux often starts at 64
    - Windows often starts at 128
    - Cisco devices start at 255
     (subtract observed TTL from these to guess OS).

- TCP window size also varies across OS.

### 3. OS Discovery using Nmap & Unicornscan

**Nmap (most widely used):**

- **Command:**
  ```
  nmap -O <target_ip>
  ```

→ Performs active OS fingerprinting using TCP/IP stack behavior.

- **Example:**

```
OS details: Linux 3.2 - 4.9
```

**Unicornscan:**

- High-performance port & OS detection tool.

**Example:**
```
unicornscan -Iv -p 1-65535 <target_ip>
```

→ Provides banners and OS guess.

### 4. OS Discovery using Nmap Script Engine (NSE)

- Nmap has scripts for service & OS detection.

**Example:**
```
nmap --script=banner <target_ip>
nmap -sV --script=os-fingerprint <target_ip>
```

- NSE helps go beyond -O and perform targeted banner grabbing.

### 5. OS Discovery using IPv6 Fingerprinting

- IPv6 stacks differ between OS vendors.

**Tools:**

- **Nmap:**
```
nmap -6 -O <target_ipv6>
```

- THC-IPv6 Toolkit for deeper analysis.

- **Example:** Different OS have different patterns in IPv6 extension headers and ICMPv6 replies.

### 6. OS Discovery with AI

- AI can help correlate multiple weak signals:

    - Banner text

    - TTL values

    - Open ports

    - Response timings

- A trained ML model could predict the most likely OS (Linux distro vs Windows version).

- **Example**: Feed features like TTL=128, open ports 135/445, banner containing “Microsoft” → AI predicts Windows Server.

---

## Scanning Beyond IDS & Firewalls.

### 1. Packet Fragmentation

- Technique: Split the TCP header into multiple small fragments.
- Why: Some IDS/firewalls fail to reassemble fragments correctly.
  
- Example with Nmap:
```
nmap -f <target_ip>
```

→ Breaks packets into small 8-byte fragments to evade detection.

### 2. Source Routing

- Allows the **attacker to specify the path** a packet takes through the network.
- Used to bypass firewalls by forcing traffic through a specific route.
- Rarely used today (mostly blocked).

### 3. Source Port Manipulation

- Some firewalls allow traffic if it comes from “trusted” ports (like DNS=53, HTTP=80, HTTPS=443).
- Scanner sets source port to these trusted ones to bypass filtering.

- Example:
```
nmap -g 53 <target_ip>
```

→ Uses UDP/53 as source port.

### 4. IP Address Decoy

- Hide the real attacker’s IP by mixing in fake IP addresses.
- IDS sees multiple sources → hard to know real one.

- Example:
```
nmap -D RND:10 <target_ip>
```

→ Generates 10 random decoy IPs.

### 5. IP Address Spoofing

- Attacker fakes the source IP address.
- Challenge: Hard to receive responses (unless MITM or with reply redirection).
- Mostly useful for DoS or blind scans.

### 6. MAC Address Spoofing

- Modify your hardware MAC address to impersonate another device.
- Useful if firewall rules are based on MAC filtering.

- **Example:**
```
ifconfig eth0 hw ether 00:11:22:33:44:55
```

**Or with macchanger:**
```
macchanger -r eth0
```

### 7. Creating Custom Packets

- IDS/firewalls may only detect common scan patterns.
- Tools like hping3, Scapy, Nemesis allow you to craft custom TCP/UDP/ICMP packets.
- Example with hping3:
```
hping3 -S -p 80 -a <spoofed_ip> <target_ip>
```

### 8. Randomizing Host Order & Sending Bad Checksums

- **Random Host Order**: IDS expecting sequential scans can be confused.
```
nmap --randomize-hosts <target_list>
```

- **Bad Checksums**: Send packets with wrong checksums → IDS logs them but real OS may accept/reconstruct.
```
nmap --badsum <target_ip>
```

### 9. Proxy Servers

- Proxy hides your IP and forwards traffic to target.
- Basic anonymity but usually logged by provider.

### 10. Proxy Chaining

- Using multiple proxies in a chain → traffic hops across multiple servers, harder to trace.
- Example: Proxychains + Nmap
```
proxychains nmap -sT <target_ip>
```

### ✅ Summary

- **Packet-level evasion** → fragmentation, spoofing, bad checksums.
- **Routing tricks** → source routing, decoys, random hosts.
- **Identity hiding** → proxies, Tor, MAC spoofing, VPNs.
- **Custom packet crafting** → hping3, Scapy.

---

## Network Scanning Countermeasures

### 1. Ping Sweep Countermeasures

👉 Attackers send multiple **ICMP Echo Requests** (ping sweep) to discover live hosts.

**📌 Countermeasures:**

- Block ICMP Echo Requests at firewalls/routers.
- Use ICMP rate limiting so multiple pings get dropped.
- Deploy IDS/IPS (e.g., Snort, Suricata) to detect unusual ICMP traffic.
- Use honeypots that respond abnormally to confuse attackers.

**⚡ Real-world:** Enterprises often disable ICMP replies on public servers so attackers can’t easily map live hosts.

### 2. Port Scanning Countermeasures

👉 Attackers scan ports with Nmap, Hping, etc.

**📌 Countermeasures:**

- **Firewalls** → Allow only required ports, block all others (default deny).
- **Port knocking** → Open ports only after a secret knock sequence.
- **Rate limiting** → Detect/reject repeated connection attempts.
- **IDS/IPS detection rules** for SYN floods, Xmas scans, etc.
- **Randomized responses** → Make results unreliable for attackers.

**⚡ Example:** A firewall dropping random SYN packets makes Nmap scans appear inconsistent.

### 3. Banner Grabbing Countermeasures

👉 Attackers connect to services (HTTP, FTP, SSH) to learn version info.

**📌 Countermeasures:**

- Disable unnecessary banners in services.
- Change default banners → e.g., Apache “ServerTokens Prod” (hides version).
- Use generic error messages instead of revealing stack traces.
- Web Application Firewalls (WAFs) → Hide backend details.

**⚡ Real-world:** Instead of showing “Apache/2.4.49 Ubuntu”, configure it to show just “Apache”.

### 4. IP Spoofing Detection Techniques

👉 Attackers spoof (fake) IP addresses to hide identity.

**📌 Detection Techniques:**

- **Ingress/Egress filtering** → ISPs block packets with invalid source IPs.
- **Packet analysis** → Check TTL values, sequence numbers, hop counts.
- **Correlation** → Compare TCP handshake responses with claimed IP.

**⚡ Example:** If a packet claims to be from 10.0.0.5 (internal host) but arrives on an external interface, it’s spoofed.

### 5. IP Spoofing Countermeasures

**📌 Countermeasures:**

- Implement RFC 3704 filtering (blocks packets with illegitimate source addresses).
- Use strong authentication (not just IP-based trust).
- Use encrypted sessions (TLS, VPNs) to prevent spoof-based attacks.
- Log correlation → Compare firewall and application logs for anomalies.

### 6. Scanning Detection and Prevention Tools

📌 Tools defenders use to catch scans:

- **IDS/IPS** → Snort, Suricata, Zeek (Bro).
- **Firewalls** → pfSense, iptables.
- **SIEMs** → Splunk, ELK Stack (alerts on scanning activity).
- **Honeypots** → Kippo, Cowrie, Dionaea (trap scanners and log them).
- **Active response tools** → Fail2Ban (blocks IP after repeated scans).

**⚡ Real-world SOC use:**

- Splunk + Suricata detect multiple failed connection attempts.
- An automated script bans the scanning IP for 24 hours.

### 🔑 Key Takeaways

- Ping sweeps can be blocked with ICMP filtering.
- Port scans → Mitigate with firewalls, port knocking, and rate limiting.
- Banner grabbing → Hide or modify banners.
- IP spoofing → Detect via filtering and packet analysis.
- Defensive tools (IDS, WAF, SIEM, honeypots) are key to detecting scans.

---




# Enumeration

## Enumeration Concepts

### 1. What is Enumeration?

- **Definition:** Enumeration is the process of **actively connecting to a target system’s services** to extract detailed information about users, groups, shares, applications, and more.
- Unlike scanning (which is more passive/stealthy), **enumeration is active and intrusive** — meaning the target will likely notice.
- Think of it like:
   - **Footprinting/Recon** = Observing a house from far away.
   - **Scanning** = Knocking on doors/windows to see which are open.
   - **Enumeration** = Entering through the open door and asking questions to find out who lives inside, how many rooms are there, and where valuables are kept.

**Goal of Enumeration:**

- Collect usernames, group names, system accounts
- Gather network resources and shares
- Extract service banners and versions
- Identify policies and settings (like password policy, SNMP info, etc.)

### 2. Techniques for Enumeration

- Enumeration techniques depend on which services/ports are open (found during scanning). Some common ones:

  **1. NetBIOS Enumeration (Port 137-139, 445)**

     - Used in Windows systems to get usernames, shares, domain info.
     - Example: Using tools like nbtstat or enum4linux.

  **2. SNMP Enumeration (Port 161/162)**

     - SNMP (Simple Network Management Protocol) often leaks network devices, routing tables, and system details if community strings (like public) are weak.

  **3. LDAP Enumeration (Port 389)**

     - Used in Active Directory environments. Can extract users, groups, policies, and domain structure.

  **4. SMTP Enumeration (Port 25)**

     - Attackers send commands like VRFY or EXPN to verify valid usernames/emails.

  **5. DNS Enumeration (Port 53)**

     - Getting info like zone transfers, hostnames, mail servers.

  **6. Banner Grabbing (Multiple Ports)**

     - Connecting to services (HTTP, FTP, SSH, etc.) to read their “banner,” which often reveals version numbers (useful for finding exploits).
 
 ### Real-World Example

👉 Imagine you’re testing a company’s internal network:

   - During scanning, you find Port 445 (SMB) open.
   - Using enumeration (```enum4linux```), you discover 5 usernames on the system: admin, guest, john, susan, itdept.
   - You then test smbclient with a blank password → You successfully log in with the guest account and see a shared folder named HR_Files.
   - That’s real enumeration: turning an open port into actual, actionable information.

## NetBIOS Enumeration 

📌 What is NetBIOS?

- NetBIOS (Network Basic Input/Output System) is an older API that allows applications on different computers to communicate over a LAN.
- It’s tightly **linked with SMB (Server Message Block)** and **Windows file/printer sharing.**
- **Runs over Ports:** 137 (NetBIOS Name), 138 (Datagram), 139 (Session) and modern SMB uses 445.

**Why Hackers Enumerate NetBIOS?**

- To get usernames, groups, network shares, domain names, and OS details.
- To check if null sessions (unauthenticated connections) are possible.
- To identify misconfigured shares that leak sensitive files.

### 1. NetBIOS Enumeration Tools

Here are the main tools hackers (and pentesters) use:

**1. nbtstat (built-in Windows command)**

  - Shows NetBIOS names and sessions.
  - Example:
   ```
   nbtstat -A <IP>
   ```

➝ Returns remote machine’s NetBIOS table (computer name, domain, logged-in users).

**2. Net View (Windows)**

  - Displays network resources and shared folders.
  - Example:
   ```
   net view \\192.168.1.10
   ```

**3. Enum4Linux (Linux)**

  - A popular tool to enumerate Windows machines via SMB/NetBIOS.
  - Example:
    ```
    enum4linux -a <IP>
    ```

**4. NBTScan (Linux/Windows)**

  - Fast scanner for NetBIOS information.
  - Example:
  ```
  nbtscan 192.168.1.0/24
  ```

**5. Metasploit Auxiliary Modules**

  - Example:
  ```
  use auxiliary/scanner/netbios/nbname
  set RHOSTS 192.168.1.0/24
  run
  ```

### 2. Enumerating User Accounts

- **Null Session Attack:** If Windows allows null sessions (```net use \\<IP>\IPC$ "" /u:""```), attackers can list user accounts.
- Example with **enum4linux:**
```
enum4linux -U 192.168.1.10
```

➝ Lists usernames available on the target system.

**Real-world risk:** With usernames, an attacker can try brute-force password attacks or password spraying.

### 3. Enumerating Shared Resources Using Net View

Windows’ ```net view``` command is simple but powerful.

- **Example:**
```
net view \\192.168.1.10
```

➝ Shows all shared folders and printers on the target machine.

- If shares are open (like ```\\192.168.1.10\Public```), attackers can mount them:
```
net use Z: \\192.168.1.10\Public
```

➝ Maps the share to drive Z: on the attacker’s machine.

**Scenario:** 

- You find a share called HR_Files that contains salary spreadsheets.
- That’s a major data exposure risk caused by weak NetBIOS/SMB configurations.

### 4. NetBIOS Enumeration using AI

This is the modern twist 🔥

AI can enhance NetBIOS enumeration in a few ways:

**1. Automated Pattern Recognition:** AI can quickly analyze outputs from enum4linux, nbtscan, or logs to identify anomalies (e.g., unexpected shares, orphan accounts).

**2. Credential Guessing Optimization:** AI models can predict the most likely weak passwords for enumerated usernames, improving brute-force efficiency.

**3. Log Analysis:** AI-driven SIEMs (like Splunk with ML) can detect suspicious enumeration attempts in real-time.

**4. Red Team AI Assistants:** Imagine feeding AI with NetBIOS scan results — it could automatically suggest exploitation paths (“These shares look world-readable, mount them” or “This user may be a domain admin candidate”).

**⚡ Example:**

- You run enum4linux and get 20 usernames.
- Feeding them into an AI assistant trained for offensive security could highlight:
  
  - Common weak passwords for those users.
  - Which accounts likely have elevated privileges.

### Real-World Example

During a pentest:

- You run ```nbtscan``` on ```192.168.1.0/24```.
- You find ```192.168.1.50``` → Computer name: **FINANCE-SERVER**, Domain: **CORP**, Logged in user: **JohnDoe**.
- You run ```enum4linux -S 192.168.1.50``` → Shared resources include FinanceDocs.
- Mount the share with ```smbclient``` and discover an Excel sheet with bank credentials.

💡 That’s how enumeration transforms a “boring open port” into critical data leakage.
