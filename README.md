# Pi-Scout 🛡️🤖

**Pi-Scout** is an autonomous, AI-powered vanguard and second-layer defense for [Pi-hole](https://pi-hole.net/). 

While static blocklists are great for known ad domains, modern ad-tech, tracking subdomains, and telemetry services constantly rotate hostnames to evade static lists. Pi-Scout sits directly behind your existing adlists: it monitors DNS queries that **slip past Pi-hole's static blocklists**, evaluating them in real-time using Google’s **Gemini AI** while strictly enforcing code-side safety guardrails to ensure household browsing, streaming, authentication, and payments never break.

It can be run interactively via its built-in, zero-dependency dark-mode web dashboard, as a standard CLI tool, or fully headless as an automated background system daemon.

---

## Key Features

* 🎯 **Second-Layer Interception:** Watches allowed lookups passing through Pi-hole and evaluates domains missed by traditional static adlists.
* 🧠 **Real-Time Gemini Evaluation:** Evaluates candidate DNS lookups in rich batches, leveraging Gemini to distinguish ad-tech/tracking subdomains from legitimate site infrastructure.
* 🛡️ **Code-Side Deterministic Guards:** AI proposes blocks, but deterministic Python code makes the final decision. Every proposal must pass:
  * Hard Whitelists & Pi-hole Allowlist checks (protects authentication, payments, CDNs, OS updates).
  * Explicit Never-Block lists (`/etc/pihole/pi_scout_never_block.txt`).
  * Dynamic Confidence Thresholds (stricter gates for wildcards vs. exact subdomains).
  * Network Telemetry Verification (inspects historical FTL database logs to ensure a domain family is pure before granting a wildcard).
* 🔄 **Graceful Wildcard Fallbacks:** If a wildcard (`||example.com^`) is deemed too risky because real site services live under that root, Pi-Scout automatically downgrades the decision and evaluates each candidate subdomain individually.
* 📁 **Multi-Category Isolation:** Outputs cleanly into individual category files (`pi_scout_ads.txt`, `pi_scout_tracking.txt`, `pi_scout_adult.txt`, `pi_scout_other.txt`), allowing you to enable or disable specific categories on the fly.
* ⚡ **Auto-Start & Seamless Boot Handoff:** Includes a persistent **Auto-Start on Boot** setting. On system reboot, it automatically executes a 30-day historical query scan before seamlessly handing off to live monitoring.
* 📊 **Modern Web Dashboard (`pi-scout-ui.py`):** Includes a zero-dependency HTTP web UI featuring live streaming events, SVG activity charts, telemetry KPI cards, real-time aggression sliders, interactive rule management, and a **Pi-hole Blocks** tab showing blocked queries caught specifically by Pi-Scout.
* 📖 **30-Day History Auditor:** Perform a comprehensive scan of your network's last 30 days of allowed queries to catch trackers that slipped past static lists in the past.

---

## Prerequisites

* **Hardware/OS:** Linux-based server running Pi-hole (Raspberry Pi OS, Debian, Ubuntu, etc.).
* **Permissions:** `sudo` / Root privileges (required to tail `/var/log/pihole/pihole.log` and write category files).
* **Python Version:** Python 3.9+
* **Dependencies:**
  * `google-genai` (Required for Gemini API access)
  * `tldextract` (Recommended for accurate TLD/registrable domain parsing)
* **API Key:** A Google Gemini API Key.

---

## Quickstart

### 1. Installation

Clone the repository to your Pi-hole host:

```bash
git clone https://github.com/YOUR_USERNAME/pi-scout.git
cd pi-scout
pip install google-genai tldextract
```

### 2. Set Your Gemini API Key

You can pass your API key as an environment variable, via a CLI argument, or store it in `~/.gemini_key`:

```bash
export GEMINI_API_KEY="your-gemini-api-key-here"
```

---

## Usage & Deployment

### 1. Running the Web Dashboard (Interactive)

To start the web dashboard with all categories enabled and a balanced wildcard aggression (7):

```bash
sudo GEMINI_API_KEY="your-gemini-api-key-here" python3 pi-scout-ui.py --all --aggression 7
```

* Open your browser and navigate to `http://<YOUR-PI-IP>:8787/`.
* Enter the access token printed in your terminal upon launch.
* **Dashboard Controls:** Start/stop live monitoring, run 30-day historical scans, toggle **Auto-Start on Boot**, adjust wildcard aggression dynamically, inspect **Pi-hole Blocks** caught by Pi-Scout, view live feed logs, unblock false positives, or clear category lists.

### 2. Running Headless / Background Mode

If you prefer to run Pi-Scout automatically in the background on system startup without keeping a terminal open, deploy it as a `systemd` service.

#### Managing as a `systemd` Service (Recommended for Auto-Boot)

1. Create a service file:

   ```bash
   sudo nano /etc/systemd/system/pi-scout.service
   ```

2. Add the configuration below (replace `your_actual_api_key_here` and update paths if needed):

   ```ini
   [Unit]
   Description=Pi-Scout Web UI Service
   After=network.target pihole-FTL.service

   [Service]
   Type=simple
   User=root
   Environment="GEMINI_API_KEY=your_actual_api_key_here"
   Environment="PYTHONUNBUFFERED=1"
   ExecStart=/usr/bin/python3 /usr/local/bin/pi-scout-ui.py --autostart
   Restart=on-failure
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now pi-scout.service
   ```

4. View live logs:

   ```bash
   sudo journalctl -u pi-scout.service -f
   ```

---

## Registering Category Lists in Pi-hole

When Pi-Scout runs for the first time, it generates empty blocklist files in `/var/www/html/`:
* `pi_scout_ads.txt`
* `pi_scout_tracking.txt`
* `pi_scout_adult.txt`
* `pi_scout_other.txt`

To connect them to Pi-hole:
1. Open your **Pi-hole Admin Dashboard**.
2. Navigate to **Domains / Adlists**.
3. Add the local file URLs for whichever categories you wish to enforce (e.g., `file:///var/www/html/pi_scout_ads.txt`).
4. Save and run a Gravity Update (`pihole -g`).

---

## False Positive Management

If Pi-Scout ever blocks a host that breaks a site or application:

1. **Via Web Dashboard:** Go to the **Rules** tab or **Allow a domain** box, enter the domain, and click **Allow**.
2. **Via CLI:** Run:
   ```bash
   sudo python3 pi-scout.py --allow app.example.com
   ```

This immediately unblocks the domain in Pi-hole, strips it from Pi-Scout's category lists, and permanently adds it to `/etc/pihole/pi_scout_never_block.txt` so it is never touched again.

---

## Wildcard Aggression Scale

| Aggression | Policy Persona | Wildcard Threshold | Exact Host Threshold |
| :---: | :--- | :---: | :---: |
| **1 – 3** | **Conservative:** Only blocks unmistakable ad networks; heavily favors exact subdomains. | ≥ 94% – 98% | ≥ 89% – 93% |
| **4 – 7** | **Balanced:** Uses wildcards for clear-cut ad roots; defaults to exact hosts for ambiguous domains. | ≥ 86% – 92% | ≥ 81% – 87% |
| **8 – 10** | **Aggressive:** Prefers wildcards for ad/tracking companies even with few observed hosts, bounded by safety floors. | ≥ 85% (Safety Floor) | ≥ 75% – 79% |

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Feel free to check out the [Issues](https://github.com/YOUR_USERNAME/pi-scout/issues) page or submit a Pull Request.

---

## License

Distributed under the **MIT License**. See `LICENSE` for more information.