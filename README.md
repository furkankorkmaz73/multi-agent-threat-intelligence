# Autonomous AI Agent for Threat Intelligence Gathering

This project implements an autonomous AI-powered agent designed to collect and analyze cybersecurity threat intelligence from multiple sources including:

- **CVE Databases (NVD)**
- **Threat Intelligence Feeds (e.g., URLHaus)**

> **Note:** Dark web scraping is planned for future improvements.  
> **Cron-based automation is implemented and actively used.**

## 🚀 Features

- 🔄 **Automated Data Fetching:** Retrieves latest CVE and threat feed data.
- 🧠 **Expandable AI/NLP Framework:** Code structure supports future integration of machine learning and NLP modules.
- 📁 **Timestamped Archiving:** Data is saved with time-based folder structure for historical tracking.
- 📊 **JSON Output:** Provides structured and standardized data for integration and future analytics.

## ⚙️ How It Works

1. **CVE Fetching:** Downloads recent vulnerability records from the National Vulnerability Database (NVD).
2. **Threat Feeds:** Pulls open-source threat data from trusted sources like URLHaus.
3. **Data Storage:** Saves fetched data in categorized JSON format using timestamped folders for organization and traceability.

## 🔁 Automation with Cron

The system is designed to run automatically using a cron job.

### Example Crontab Entry (every 8 hours):
```cron
0 */8 * * * cd /home/youruser/path/to/project && /usr/bin/go run main.go >> logs/test.log 2>&1
````

### For testing (every 1 minute):

```cron
*/1 * * * * cd /home/youruser/path/to/project && /usr/bin/go run main.go >> logs/test.log 2>&1
```

### Notes:

* Ensure the `cron` service is running:

  ```bash
  sudo service cron start
  ```
* On WSL systems, you can add this line to your `~/.bashrc` to auto-start cron:

  ```bash
  sudo service cron status >/dev/null || sudo service cron start
  ```

## 📈 Future Improvements

* [ ] Dark Web Forum scraping via Tor
* [ ] NLP-based content classification (e.g., threat type detection)
* [ ] Machine Learning for dynamic threat scoring
* [ ] Email alerts and web-based dashboard