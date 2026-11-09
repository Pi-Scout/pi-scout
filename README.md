# Pi-Scout 🛡️🤖

**Pi-Scout** is an autonomous, AI-powered vanguard for [Pi-hole](https://pi-hole.net/). While static blocklists are great for known ad domains, modern ad-tech, tracking subdomains, and telemetry services constantly shift to evade static lists. 

Pi-Scout acts as an intelligent real-time scanner that analyzes DNS query behavior using Google’s **Gemini AI**, while strictly enforcing code-side safety guardrails to ensure household browsing, streaming, authentication, and payments never break.

It can be run as a lightweight CLI daemon or via its built-in, zero-dependency dark-mode web dashboard.

---

## Key Features

* 🧠 **Real-Time Gemini Evaluation:** Evaluates candidate DNS lookups in rich batches, leveraging Gemini to distinguish ad-tech/tracking subdomains from legitimate site infrastructure.
* 🛡️ **Code-Side Deterministic Guards:** AI proposes blocks, but deterministic Python code makes the final decision. Every proposal must pass:
  * Hard Whitelists & Pi-hole Allowlist checks (protects authentication, payments, CDNs, OS updates).
  * Explicit Never-Block lists (`/etc/pihole/pi_scout_never_block.txt`).
  * Dynamic Confidence Thresholds (stricter gates for wildcards vs. exact subdomains).
  * Network Telemetry Verification (inspects historical FTL database logs to ensure a domain family is pure before granting a wildcard).
* 🔄 **Graceful Wildcard Fallbacks:** If a wildcard (`||example.com^`) is deemed too risky because real site services live under that root, Pi-Scout automatically downgrades the decision and evaluates each candidate subdomain individually.
* 📁 **Multi-Category Isolation:** Outputs cleanly into individual category files (`pi_scout_ads.txt`, `pi_scout_tracking.txt`, `pi_scout_adult.txt`, `pi_scout_other.txt`), allowing you to enable or disable specific categories on the fly.
* 📊 **Modern Web Dashboard (`pi-scout-ui.py`):** Includes a zero-dependency HTTP web UI featuring live streaming events, SVG activity charts, telemetry KPI cards, real-time aggression sliders, and interactive rule management.
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

## Usage

### Running the Web Dashboard (Recommended)

To start the web dashboard with all categories enabled and a balanced wildcard aggression (7):

```bash
sudo python3 pi-scout-ui.py --all --aggression 7
```

* Open your browser and navigate to `http://<YOUR-PI-IP>:8787/`.
* Enter the access token printed in your terminal upon launch.
* **Dashboard Controls:** Start/stop live monitoring, run 30-day historical scans, adjust wildcard aggression dynamically, view live feed logs, unblock false positives, or clear category lists.

### Running Headless CLI Mode

If you prefer to run Pi-Scout strictly as a background daemon without the UI:

```bash
# Run live hunter mode
sudo python3 pi-scout.py --all --aggression 7

# Run a one-time audit on the last 30 days of lookups
sudo python3 pi-scout.py --audit --all
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