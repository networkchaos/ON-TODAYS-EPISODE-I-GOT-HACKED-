# n 2025-11-02 DATE I WAS HACKED

> **Type:** Forensic / Incident Response Report — Research notebook & procedure
> **Author:** networkchaos (Kali) — working notes prepared for GitHub / lab record
> **Date:** 2025-11-02
> **Device under test:** Android phone (serial `0N14C23Ixxxxxxxxx` / TCP `192.168.1.xxx:5555`)
> **Tools used:** Mobile Verification Toolkit (MVT) v2.6.1, ADB (android-tools), standard Linux utilities (tar, sha256sum, jq), VirusTotal / URL scanners (public), WHOIS/rdap, crt.sh lookup, and short-link expansion

---

## TL;DR (Executive summary)

I discovered that my email account had been used to send a malicious shortened link (`https://rb.gy/n3c7gd`) which expanded to `https://ohj6rr.trueloves.live/18/?sub1=con&ext_click_id=...`. I investigated the phishing link, tracked its hosting (Cloudflare IP `104.26.2.41`), reported and prepared abuse leads, and then performed an on‑device forensic scan of my Android phone using MVT to check for spyware or compromise.

* MVT successfully ran and **produced 6 detections** (indicators of interest).
* The notable findings were several apps with `REQUEST_INSTALL_PACKAGES` app-op access (apps that can install APKs): `cn.xender`, `com.anilab.android`, `com.android.chrome`, `com.brave.browser`, `com.snaptube.premium`.
* I preserved the full MVT results (`~/mvt-results`) and archived them: `mvt-results-2025-11-02.tar.gz` (sha256 saved).
* I resolved several tool-chain issues (virtualenv path, `adb` unauthorized, ADB TCP forwarding, “device busy” module errors) and documented the commands and fixes.

This report documents what I did, why, what I found, the commands I used, problems encountered, mitigation steps, and suggested next steps (forensic escalation, takedowns, long-term remediation).

---

## Scope & Objective

**Goal:** Investigate suspected compromise resulting from malicious emails sent from my account and determine whether the Android device was targeted/compromised by advanced spyware or other malware.

**Scope of work performed today:**

1. Expand and analyze the short link received via email.
2. Query hosting and certificate information for the destination domain.
3. Configure a Linux workstation (Kali) with ADB and MVT.
4. Connect to the Android device (USB and TCP) and collect artifacts via MVT (`check-adb`).
5. Interpret MVT results and identify suspicious packages/app ops.
6. Archive and preserve all artifacts for investigation.

**What this report does NOT show:** Full forensic unpacking of suspect APKs (static/dynamic analysis), nor legal actions taken — it is a technical record for replication and escalation.

---

## Timeline (key timestamps — local timezone UTC+3)

* **2025-11-02 08:18:01** — URL scan for `https://rb.gy/n3c7gd` revealed redirect target `ohj6rr.trueloves.live` and Cloudflare IP `104.26.2.41`.
* **2025-11-02 08:47 — 09:16** — Installed MVT, downloaded IoC packages (Pegasus, Predator, Candiru, etc.), and started `mvt-android check-adb`.
* **2025-11-02 09:02:17** — Initial “device busy” error encountered; resolved by specifying device serial.
* **2025-11-02 09:16:53** — MVT finished collection and reported **6 detections**.
* **2025-11-02 09:16:53** — `timeline_detected.csv` entries show multiple `REQUEST_INSTALL_PACKAGES` access events (see Findings).

---

## Environment (host & device)

**Host (forensic workstation):**

* OS: Kali Linux (user `networkchaos`)
* Python venv: `~/Desktop/mvt-venv`
* MVT version: `2.6.1`
* Important commands installed: `android-tools-adb`, `libusb-1.0-0-dev`, `openjdk-11-jre-headless`, `jq`, `tar`, `sha256sum`

**Device (target phone):**

* Model: `RMX3834` (from `adb shell getprop ro.product.model`)
* ADB endpoints visible: `0N14C23Ixxxxxxxxx` (USB) and `192.168.1.xxx:5555` (TCP)
* MVT results path: `~/mvt-results` on host
* Evidence archive: `~/mvt-results-2025-11-02.tar.gz` (sha256 saved)

---

## Tools & resources used

* Mobile Verification Toolkit (MVT) — [https://mvt.re](https://mvt.re) (v2.6.1)
* Android Debug Bridge (adb) — platform-tools / android-tools-adb
* WHOIS/RDAP (ARIN, registrar lookups)
* Certificate Transparency (crt.sh)
* URL scanners (VirusTotal / urlscan / public URL scans)
* Linux utilities: `tar`, `sha256sum`, `jq`, `sed`, `awk`, `grep`, `ls`, `cat`
* Optional analysis tools suggested: `apktool`, `jadx`, `VirusTotal` UI or API for APK hash scanning

---

## What I found (detailed findings)

### Link & hosting analysis

* Short link: `https://rb.gy/n3c7gd` → expanded to `https://ohj6rr.trueloves.live/18/?sub1=con&ext_click_id=...`
* Observed hosting: IP `104.26.2.41` (Cloudflare CDN) — this IP belongs to Cloudflare (ASN 13335). Cloudflare masks the origin server IP.
* TLS certificate: Issued by Google Trust Services for `trueloves.live`, `*.trueloves.live`.

**Interpretation:** The attacker used rb.gy to hide the final destination and `trueloves.live` behind Cloudflare. Attribution to an individual or origin server requires cooperation from Cloudflare (abuse logs) and/or rb.gy and usually a legal process.

---

### MVT scan summary (high level)

* MVT loaded **10,885 unique IoCs** (Pegasus, Predator, Candiru, Quadream, etc.).
* MVT scanned ~310,724 files on the device and produced output files for many modules (apps list, dumpsys output, logcat, files list, etc.).
* MVT reported **6 detections**. The most actionable, human-readable detection output appears in `timeline_detected.csv`.

Excerpt (from `timeline_detected.csv` first 9 rows):

```
"Device Local Timestamp","Plugin","Event","Description"
"2025-06-07 14:27:44.141000","DumpsysAppOps","Reject","cn.xender access to REQUEST_INSTALL_PACKAGES: Reject"
"2025-06-07 14:41:27.742000","DumpsysAppOps","Access","cn.xender access to REQUEST_INSTALL_PACKAGES: Access"
"2025-07-20 16:49:05.025000","DumpsysAppOps","Access","com.anilab.android access to REQUEST_INSTALL_PACKAGES: Access"
"2025-08-25 23:58:58.343000","DumpsysAppOps","Reject","com.android.chrome access to REQUEST_INSTALL_PACKAGES: Reject"
"2025-08-25 23:59:16.232000","DumpsysAppOps","Access","com.android.chrome access to REQUEST_INSTALL_PACKAGES: Access"
"2025-09-13 14:38:14.474000","DumpsysAppOps","Reject","com.brave.browser access to REQUEST_INSTALL_PACKAGES: Reject"
"2025-10-29 15:51:31.198000","DumpsysAppOps","Access","com.brave.browser access to REQUEST_INSTALL_PACKAGES: Access"
"2025-10-29 15:55:11.582000","DumpsysAppOps","Reject","com.snaptube.premium access to REQUEST_INSTALL_PACKAGES: Reject"
"2025-10-29 15:55:24.978000","DumpsysAppOps","Access","com.snaptube.premium access to REQUEST_INSTALL_PACKAGES: Access"
```

**Interpretation:** Several apps requested and in some instances were granted the `REQUEST_INSTALL_PACKAGES` operation — which allows an app to install APK files (sideload) or behave like an installer. This is not a definitive indicator of advanced spyware, but it is high‑risk because malicious installers or repackaged APKs could be pushed this way. `com.snaptube.premium` is especially suspicious (Snaptube variants are commonly distributed from outside the Play Store and often adware/malicious).

---

## Artifacts preserved

* Full MVT results directory: `~/mvt-results/` (contains `logcat.txt`, `dumpsys_*.json`, `timeline.csv`, `timeline_detected.csv`, `files.json`, `packages.json`, etc.)
* Archive: `~/mvt-results-2025-11-02.tar.gz`
* SHA256 of archive stored in `~/mvt-results-2025-11-02.tar.gz.sha256`
* Pulled APKs (if any; recommended to pull suspicious APKs before uninstall) — (use `adb shell pm path <package>` then `adb pull`).

---

## Commands & procedures used (step-by-step, copy-pasteable)

> These are the canonical commands I used — paste them into your terminal on Kali. Replace IP/serial where noted.

### Host preparation & MVT install

```bash
# apt prerequisites
sudo apt update
sudo apt install -y python3 python3-venv python3-pip android-tools-adb libusb-1.0-0-dev openjdk-11-jre-headless unzip jq

# create virtualenv and activate
cd ~/Desktop
python3 -m venv mvt-venv
source ~/Desktop/mvt-venv/bin/activate

# upgrade pip and install MVT
pip install --upgrade pip
pip install mvt

# confirm
which mvt-android
mvt-android --help
```

### Fix common ADB/udev issues (if needed)

```bash
# list USB devices
lsusb

# example udev rule (replace vendor id from lsusb)
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -aG plugdev $USER
# log out/in to apply group change
```

### Clear old ADB keys and restart ADB

```bash
rm -f ~/.android/adbkey*
adb kill-server
adb start-server
adb devices
```

### Connect device via USB (authorize on phone) or via TCP/IP

```bash
# (if USB authorized) switch ADB to TCP mode on device:
adb tcpip 5555

# find phone IP on device wifi or via adb:
adb shell ip -f inet addr show wlan0 | awk '/inet /{print $2}' | cut -d/ -f1
# example result: 192.168.1.xxx

# connect over network
adb connect 192.168.1.xxx:5555
adb devices
# confirm device: 192.168.1.xxx:5555 device

# if you end up with two endpoints (USB and TCP), prefer specifying serial to avoid "device busy"
mvt-android check-adb --serial 192.168.1.xxx:5555 --output ~/mvt-results -v
```

### MVT run & indicators

```bash
# download IoCs
mvt-android download-iocs

# run scan (targeted)
mkdir -p ~/mvt-results
mvt-android check-adb --serial 192.168.1.xxx:5555 --output ~/mvt-results -v

# optional: download installed apks
mkdir -p ~/mvt-results/apks
mvt-android download-apks --serial 192.168.1.xxx:5555 --output ~/mvt-results/apks
```

### Archive & preserve results

```bash
tar -czvf ~/mvt-results-$(date -I).tar.gz ~/mvt-results
sha256sum ~/mvt-results-$(date -I).tar.gz > ~/mvt-results-$(date -I).tar.gz.sha256
```

### Inspecting results (quick analysis)

```bash
cd ~/mvt-results
# list files
ls -lah

# view detected timeline (top lines)
sed -n '1,200p' timeline_detected.csv

# pretty-print detection JSONs if any
jq '.' *detected*.json | less -R

# view the main JSON
less android_adb_results.json
```

### Investigate suspicious packages (example using `com.snaptube.premium`)

```bash
# list user packages
adb -s 192.168.1.xxx:5555 shell pm list packages -3

# get package info (installer, timestamps, signatures)
adb -s 192.168.1.xxx:5555 shell dumpsys package com.snaptube.premium | sed -n '1,200p'

# get apk path and pull it
adb -s 192.168.1.xxx:5555 shell pm path com.snaptube.premium
# output: package:/data/app/~~.../com.snaptube.premium-1/base.apk
adb -s 192.168.1.xxx:5555 pull /data/app/.../base.apk ~/Desktop/snaptube.apk

# hash the apk for VirusTotal
sha256sum ~/Desktop/snaptube.apk
```

### Neutralize or remove suspicious apps (if self-remediating)

```bash
# force stop
adb -s 192.168.1.xxx:5555 shell am force-stop com.snaptube.premium

# disable (non-destructive)
adb -s 192.168.1.xxx:5555 shell pm disable-user --user 0 com.snaptube.premium

# uninstall for current user
adb -s 192.168.1.xxx:5555 shell pm uninstall --user 0 com.snaptube.premium
```

### Useful search commands on the phone for suspicious files / extensions

```bash
# search for common malicious filename patterns and extensions
adb -s 192.168.1.xxx:5555 shell find /sdcard /data -type f -iname "*.apk" -o -iname "*.dex" -o -iname "*snaptube*" -o -iname "*payload*" 2>/dev/null

# search for executables in tmp and media folders
adb -s 192.168.1.xxx:5555 shell find /data/local/tmp /sdcard -perm -u=x -type f 2>/dev/null

# search for suspicious file extensions
adb -s 192.168.1.xxx:5555 shell find / -type f \( -iname "*.sh" -o -iname "*.bin" -o -iname "*.so" \) 2>/dev/null | sed -n '1,200p'
```

### Misc: open system update UI (cannot force OTA)

```bash
# open update settings (manual user action required)
adb -s 192.168.1.xxx:5555 shell am start -a android.settings.SYSTEM_UPDATE_SETTINGS
```

---

## Problems / bugs encountered & how I fixed them (lessons learned)

1. **`mvt-android: command not found`**

   * Cause: virtual environment not activated / venv path changed.
   * Fix: recreate or activate venv with `source ~/Desktop/mvt-venv/bin/activate` then `pip install mvt`.

2. **`adb devices` returned `unauthorized`**

   * Cause: ADB RSA fingerprint prompt not accepted on device OR old corrupted keys.
   * Fixes: revoke USB debugging on phone (Developer options → Revoke USB debugging authorizations), remove `~/.android/adbkey*` on host, reconnect & accept RSA key.

3. **`Device is busy` error in MVT (chrome_history module)**

   * Cause: multiple ADB endpoints present (USB and TCP), or app DB files locked by Chrome.
   * Fixes:

     * Use `mvt-android --serial <serial>` to pin which device to talk to.
     * Unplug USB or `adb disconnect <ip>:5555` so only one endpoint exists.
     * Force-stop Chrome on phone before running that module: `adb shell am force-stop com.android.chrome`.
     * Option to skip the failing module: `--skip-modules chrome_history`.

4. **ADB TCP placeholder confusion (`<DEVICE_IP>`)**

   * Cause: literal angle-bracket placeholders used in shell.
   * Fix: replace with actual IP: `adb connect 192.168.1.xxx:5555`.

5. **Multiple adb servers / processes interfering**

   * Fix: kill stray adb processes (`sudo killall adb`) and restart adb server as the normal user.

---

## What I could have done (and plan to do next)

**Further technical actions that provide deeper evidence or more coverage:**

* Pull suspicious APKs and perform static/dynamic analysis (apktool, jadx, strings, class/method inspection). Upload hash to VirusTotal & Koodous.
* Use passive DNS, historical DNS (SecurityTrails, VirusTotal passive DNS) to search for previous origin IPs for `trueloves.live`.
* Query certificate transparency logs (crt.sh) for `trueloves.live` for related SANs.
* Request logs from rb.gy (shortener) and Cloudflare via their abuse reporting channels — rb.gy can map the short link to the account that created it and Cloudflare may preserve origin logs (requires law enforcement subpoena for detailed customer logs in many jurisdictions).
* If IoCs tie to an advanced spyware family (Pegasus, Candiru, Predator), escalate to a mobile-forensics specialist and law enforcement rather than attempting full cleanup myself.

**Operational security (what I will change):**

* Use a known-good machine (air-gapped or clean VM) for credential changes and bank interactions.
* Rotate all critical passwords and rotate 2FA credentials using a secure device or hardware token.

---

## Recommended next steps (actionable)

1. **If you want to preserve the device for a formal investigation:** stop any destructive actions. Keep `~/mvt-results` and the device intact. Immediately contact a reputable mobile forensics lab or Amnesty/MVT assistance links. Provide the full archive and note time windows.

2. **If you will self-remediate:**

   * Archive the MVT results (done).
   * Pull suspicious APKs & compute their hashes for uploading to VirusTotal.
   * Uninstall suspicious apps (`pm uninstall --user 0 <package>`), then factory reset device from UI and reinstall only from the Play Store.

3. **Report the phishing infrastructure:**

   * Cloudflare abuse: `abuse@cloudflare.com` or [https://abuse.cloudflare.com/](https://abuse.cloudflare.com/) — include expanded URL, timestamps, and MVT artifacts.
   * rb.gy shortener: use rb.gy reporting endpoint (report short link) with details.
   * Registrar/Maintainer of `trueloves.live` via RDAP / WHOIS.

4. **Notify contacts:** Inform people who received emails/links to ignore them, and request originals with headers to help tracing.

---

## Appendix A — Sample evidence e-mail template (to Cloudflare / rb.gy)

```text
Subject: Malicious phishing URL hosted via Cloudflare / shortener — request takedown

Hello,

A phishing URL shortened via https://rb.gy/n3c7gd redirects to https://ohj6rr.trueloves.live/18/?sub1=con&ext_click_id=... .
This URL was distributed from a compromised email account belonging to me and used to phish my contacts.

Detection timestamp: 2025-11-02 08:18:01 (UTC+3)
Cloudflare hosting IP observed: 104.26.2.41 (ASN 13335)
Evidence: Original phishing emails with full headers (available upon request), MVT scan results archive attached: mvt-results-2025-11-02.tar.gz (sha256: <paste_sha256_here>)

Please investigate and suspend the domain/page. If you need additional evidence or a law enforcement request, I will cooperate.

Regards,
[Your name] — [contact info]
```

---

## Appendix B — Quick commands cheat-sheet (compact)

```text
# Activate venv
source ~/Desktop/mvt-venv/bin/activate

# Start/stop adb
adb kill-server
adb start-server

# List devices
adb devices

# Connect over TCP
adb tcpip 5555
adb connect 192.168.1.xxx:5555

# Run MVT (targeted)
mvt-android download-iocs
mvt-android check-adb --serial 192.168.1.xxx:5555 --output ~/mvt-results -v

# Archive results
tar -czvf ~/mvt-results-$(date -I).tar.gz ~/mvt-results
sha256sum ~/mvt-results-$(date -I).tar.gz

# Pull APK
adb -s 192.168.1.xxx:5555 shell pm path com.snaptube.premium
adb -s 192.168.1.xxx:5555 pull /data/app/.../base.apk ~/Desktop/snaptube.apk
sha256sum ~/Desktop/snaptube.apk

# Disable/uninstall app
adb -s 192.168.1.xxx:5555 shell pm disable-user --user 0 com.snaptube.premium
adb -s 192.168.1.xxx:5555 shell pm uninstall --user 0 com.snaptube.premium
```

---

## Appendix C — Screenshots & images

I did not include binary screenshots in this text export. If you want images in the GitHub README:

* Take screenshots of key terminal outputs on your host (e.g., `adb devices` showing `device`, `mvt-android` runlog, `timeline_detected.csv` snippet) and place them under `images/` in the repo.
* Example command to capture a screenshot of the phone (via adb) and pull it:

  ```bash
  adb -s 192.168.1.xxx:5555 shell screencap -p /sdcard/screen.png
  adb -s 192.168.1.xxx:5555 pull /sdcard/screen.png ~/Desktop/screen.png
  ```
* In README, reference images like `![MVT findings](images/timeline_detected.png)`.

---

## Legal & ethical note

* Only scan devices you own or have explicit permission to analyze.
* Do not attempt retaliatory actions (hacking back) against suspected infrastructure. Contact appropriate abuse desks and law enforcement for legal takedown and investigative support.
* If the IoCs point to targeted commercial spyware (e.g., Pegasus / Candiru / Predator), escalate to specialized mobile forensics and law enforcement immediately.

---

## Closing notes — what I would add to the repo

* `README.md` (this document) — placed at repo root.
* `evidence/` — store `mvt-results-2025-11-02.tar.gz` (or better: store on offline/airgapped medium, not public GitHub). **Do not** publish sensitive archives publicly.
* `images/` — screenshots of critical outputs (timeline_detected snippet, adb devices, whois output, urlscan).
* `notes/` — a short log of exact commands executed (already recorded above) and any communications with providers (rb.gy / Cloudflare).

---

If you want, I will:

* Convert this into a ready-to-commit `README.md` file and place it in a single code block so you can copy & paste to your repo.
* Redact any sensitive fields (phone serial, full URLs) for public posting and produce a sanitized version for GitHub.
* Produce a separate private evidence README with exact archive checksums to keep offline.

Which would you like me to do next?
