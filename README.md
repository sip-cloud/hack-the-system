# Hack The System 🔍

> OSINT username reconnaissance tool — black & pink terminal UI

Search a username across **34 platforms** simultaneously including Instagram, GitHub, TikTok, Reddit, Twitch, Steam, Spotify, LinkedIn, and more.

---

## Install (macOS)

```bash
git clone https://github.com/YOUR_USERNAME/hack-the-system
cd hack-the-system
pip3 install -r requirements.txt
chmod +x hts.py

# Add to PATH (run once)
ln -sf "$(pwd)/hts.py" ~/.local/bin/hts
```

## Install (Windows)

```bat
git clone https://github.com/YOUR_USERNAME/hack-the-system
cd hack-the-system
install.bat
```

---

## Usage

```bash
hts
```

- **[1] Search Username** — scan across all or selected platforms
- **[2] List Platforms** — see all 34 supported sites
- **[3] About**
- Results optionally exported to `~/Downloads`

---

## Platforms

| Category     | Platforms |
|--------------|-----------|
| Social       | Instagram, Twitter/X, TikTok, Snapchat, Pinterest, Tumblr, Facebook |
| Professional | LinkedIn, Medium, Dev.to, Product Hunt, About.me |
| Tech         | GitHub, GitLab, Keybase, Replit, Hacker News, HackerOne, Bugcrowd |
| Gaming       | Twitch, Steam, Roblox |
| Media        | YouTube, Spotify, SoundCloud, Vimeo, Flickr, Behance, Dribbble |
| Other        | Reddit, Patreon, Telegram, Mastodon, Linktree |

---

## Requirements

- Python 3.8+
- `requests`
- `rich`

---

> For ethical and authorised use only.

---

*Maintained by Winston Churchill*
