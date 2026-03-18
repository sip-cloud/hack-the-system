#!/usr/bin/env python3
"""
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗    ████████╗██╗  ██╗███████╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ╚══██╔══╝██║  ██║██╔════╝
  ███████║███████║██║     █████╔╝        ██║   ███████║█████╗
  ██╔══██║██╔══██║██║     ██╔═██╗        ██║   ██╔══██║██╔══╝
  ██║  ██║██║  ██║╚██████╗██║  ██╗       ██║   ██║  ██║███████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚══════╝
   ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
   ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
   ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
   ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
   ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
   ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝

  OSINT Username Reconnaissance Tool
  For ethical and authorized use only.
"""

import sys
import os
import time
import threading
import concurrent.futures
from datetime import datetime
from pathlib import Path


def _install_deps():
    import subprocess
    needed = []
    try:
        import requests  # noqa: F401
    except ImportError:
        needed.append("requests")
    try:
        import rich  # noqa: F401
    except ImportError:
        needed.append("rich")
    if needed:
        print(f"Installing dependencies: {', '.join(needed)} ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + needed
        )


_install_deps()

import requests  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.progress import (  # noqa: E402
    Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn,
)
from rich.text import Text  # noqa: E402
from rich import box  # noqa: E402
from rich.prompt import Prompt, Confirm  # noqa: E402
from rich.align import Align  # noqa: E402
from rich.rule import Rule  # noqa: E402

# ─────────────────────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────────────────────
PINK    = "color(198)"   # hot pink  #FF1493
LPINK   = "color(218)"   # light pink
WHITE   = "white"
DIM     = "dim white"

console = Console()

BANNER = (
    f"\n"
    f"[{PINK}]  ██╗  ██╗ █████╗  ██████╗██╗  ██╗    ████████╗██╗  ██╗███████╗[/]\n"
    f"[{LPINK}]  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ╚══██╔══╝██║  ██║██╔════╝[/]\n"
    f"[{PINK}]  ███████║███████║██║     █████╔╝        ██║   ███████║█████╗  [/]\n"
    f"[{LPINK}]  ██╔══██║██╔══██║██║     ██╔═██╗        ██║   ██╔══██║██╔══╝  [/]\n"
    f"[{PINK}]  ██║  ██║██║  ██║╚██████╗██║  ██╗       ██║   ██║  ██║███████╗[/]\n"
    f"[{LPINK}]  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚══════╝[/]\n"
    f"[{PINK}]   ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗[/]\n"
    f"[{LPINK}]   ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║[/]\n"
    f"[{PINK}]   ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║[/]\n"
    f"[{LPINK}]   ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║[/]\n"
    f"[{PINK}]   ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║[/]\n"
    f"[{LPINK}]   ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝[/]\n"
)

# ─────────────────────────────────────────────────────────────
# PLATFORMS  (35 platforms across 6 categories)
# ─────────────────────────────────────────────────────────────
#
# check_type:
#   "status"  – found if HTTP status == found_code
#   "content" – found if found_code AND none of not_found_strings in body
#
PLATFORMS = [
    # ── Social ───────────────────────────────────────────────
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{}/",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["sorry, this page"],
    },
    {
        "name": "Twitter / X",
        "url": "https://x.com/{}",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["this account doesn't exist"],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{}",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["couldn't find this account"],
    },
    {
        "name": "Snapchat",
        "url": "https://www.snapchat.com/add/{}",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{}/",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Tumblr",
        "url": "https://{}.tumblr.com",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["there's nothing here"],
    },
    {
        "name": "Facebook",
        "url": "https://www.facebook.com/{}",
        "category": "Social",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["page not found"],
    },
    # ── Professional ─────────────────────────────────────────
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{}/",
        "category": "Professional",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{}",
        "category": "Professional",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Dev.to",
        "url": "https://dev.to/{}",
        "category": "Professional",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Product Hunt",
        "url": "https://www.producthunt.com/@{}",
        "category": "Professional",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "About.me",
        "url": "https://about.me/{}",
        "category": "Professional",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    # ── Tech / Dev ────────────────────────────────────────────
    {
        "name": "GitHub",
        "url": "https://github.com/{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["not a keybase user"],
    },
    {
        "name": "Replit",
        "url": "https://replit.com/@{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Hacker News",
        "url": "https://news.ycombinator.com/user?id={}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["no such user"],
    },
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com/{}",
        "category": "Tech",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    # ── Gaming ────────────────────────────────────────────────
    {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{}",
        "category": "Gaming",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{}",
        "category": "Gaming",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["the specified profile could not be found"],
    },
    {
        "name": "Roblox",
        "url": "https://www.roblox.com/users/profile?username={}",
        "category": "Gaming",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    # ── Media / Creative ──────────────────────────────────────
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Spotify",
        "url": "https://open.spotify.com/user/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "SoundCloud",
        "url": "https://soundcloud.com/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Vimeo",
        "url": "https://vimeo.com/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Flickr",
        "url": "https://www.flickr.com/people/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Behance",
        "url": "https://www.behance.net/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Dribbble",
        "url": "https://dribbble.com/{}",
        "category": "Media",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    # ── Other ─────────────────────────────────────────────────
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{}",
        "category": "Other",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["nobody on reddit goes by that name"],
    },
    {
        "name": "Patreon",
        "url": "https://www.patreon.com/{}",
        "category": "Other",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Telegram",
        "url": "https://t.me/{}",
        "category": "Other",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["if you have telegram"],
    },
    {
        "name": "Mastodon",
        "url": "https://mastodon.social/@{}",
        "category": "Other",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": [],
    },
    {
        "name": "Linktree",
        "url": "https://linktr.ee/{}",
        "category": "Other",
        "found_code": 200,
        "not_found_code": 404,
        "not_found_strings": ["sorry, this page isn"],
    },
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

CATEGORIES = sorted({p["category"] for p in PLATFORMS})


# ─────────────────────────────────────────────────────────────
# CORE LOGIC
# ─────────────────────────────────────────────────────────────

def check_platform(platform: dict, username: str, timeout: int = 10) -> dict:
    url = platform["url"].format(username)
    result = {
        "name":     platform["name"],
        "category": platform["category"],
        "url":      url,
        "status":   "unknown",
        "code":     None,
        "error":    None,
    }
    try:
        session = requests.Session()
        resp = session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        result["code"] = resp.status_code

        if resp.status_code == platform.get("not_found_code", 404):
            result["status"] = "not_found"
        elif resp.status_code == platform.get("found_code", 200):
            body = resp.text.lower()
            nf_strings = platform.get("not_found_strings", [])
            if any(s in body for s in nf_strings):
                result["status"] = "not_found"
            else:
                result["status"] = "found"
        elif resp.status_code in (403, 429, 503):
            result["status"] = "rate_limited"
        else:
            result["status"] = "unknown"

    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = "timed out"
    except requests.exceptions.ConnectionError:
        result["status"] = "error"
        result["error"] = "connection error"
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)[:60]

    return result


def run_scan(username: str, platforms: list) -> list:
    results = []
    lock = threading.Lock()

    with Progress(
        SpinnerColumn(style=PINK),
        TextColumn(f"[{PINK}]{{task.description}}[/]"),
        BarColumn(bar_width=28, style=PINK, complete_style=LPINK),
        TaskProgressColumn(style=LPINK),
        TextColumn(f"[{LPINK}]{{task.completed}}/{{task.total}}[/]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Scanning [{LPINK}]{username}[/] across {len(platforms)} platforms",
            total=len(platforms),
        )

        def _check(p):
            r = check_platform(p, username)
            with lock:
                results.append(r)
                progress.advance(task)
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(_check, p) for p in platforms]
            concurrent.futures.wait(futures)

    return results


# ─────────────────────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────────────────────

def _divider():
    console.print(f"[{PINK}]{'━' * 64}[/]")


def show_banner():
    console.clear()
    console.print(BANNER)
    console.print(Align.center(f"[{PINK}]{'━' * 60}[/]"))
    console.print(Align.center(f"[{LPINK}] OSINT Username Reconnaissance Tool [/]"))
    console.print(Align.center(f"[{DIM}] Check usernames across {len(PLATFORMS)} platforms [/]"))
    console.print(Align.center(f"[{PINK}]{'━' * 60}[/]"))
    console.print()


def show_menu():
    t = Text()
    t.append("  [1]", style=PINK + " bold"); t.append("  Search Username\n", style=WHITE)
    t.append("  [2]", style=PINK + " bold"); t.append("  List All Platforms\n", style=WHITE)
    t.append("  [3]", style=PINK + " bold"); t.append("  About\n", style=WHITE)
    t.append("  [0]", style=PINK + " bold"); t.append("  Exit", style=WHITE)
    console.print(Panel(t, title=f"[{PINK}] MAIN MENU [/]", border_style=PINK, padding=(1, 4)))


def display_results(username: str, results: list) -> list:
    found        = [r for r in results if r["status"] == "found"]
    not_found    = [r for r in results if r["status"] == "not_found"]
    errors       = [r for r in results if r["status"] not in ("found", "not_found")]

    summary = Text()
    summary.append("  Target  : ", style=DIM); summary.append(f"{username}\n", style=LPINK + " bold")
    summary.append("  Found   : ", style=DIM); summary.append(f"{len(found)}", style=PINK + " bold")
    summary.append(f"  /  {len(results)} checked   ", style=DIM)
    summary.append(f"{len(not_found)} not found  ", style=DIM)
    summary.append(f"{len(errors)} errors/rate-limited", style=DIM)

    console.print()
    console.print(Panel(summary, title=f"[{PINK}] SCAN COMPLETE [/]", border_style=PINK, padding=(1, 2)))
    console.print()

    if found:
        table = Table(
            title=f"[{PINK}] ✓  FOUND ON {len(found)} PLATFORM{'S' if len(found) != 1 else ''} [/]",
            box=box.HEAVY_EDGE,
            border_style=PINK,
            title_style=PINK + " bold",
            header_style=LPINK + " bold",
            show_lines=True,
        )
        table.add_column("Platform",  style=LPINK + " bold", min_width=15)
        table.add_column("Category",  style="dim " + LPINK,  min_width=12)
        table.add_column("URL",       style=LPINK,            min_width=42)

        for r in sorted(found, key=lambda x: (x["category"], x["name"])):
            table.add_row(
                f"[{PINK}] ★ [/][{LPINK}]{r['name']}[/]",
                r["category"],
                r["url"],
            )
        console.print(table)
    else:
        console.print(Panel(
            f"[{DIM}]  No accounts found for '{username}' on any platform.[/]",
            border_style="dim", title=f"[dim] NOT FOUND [/]",
        ))
    console.print()
    return found


def save_results(username: str, results: list) -> str:
    found = [r for r in results if r["status"] == "found"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = str(Path.home() / "Downloads" / f"hts_{username}_{timestamp}.txt")

    with open(fname, "w") as f:
        f.write("=" * 64 + "\n")
        f.write("HACK THE SYSTEM  ─  OSINT Username Report\n")
        f.write("=" * 64 + "\n")
        f.write(f"Target  : {username}\n")
        f.write(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Found   : {len(found)} / {len(results)} platforms\n")
        f.write("=" * 64 + "\n\n")

        if found:
            f.write("FOUND ON:\n" + "─" * 40 + "\n")
            for r in sorted(found, key=lambda x: x["name"]):
                f.write(f"  [✓] {r['name']:<22} {r['url']}\n")
            f.write("\n")

        f.write("FULL RESULTS:\n" + "─" * 40 + "\n")
        icons = {"found": "✓", "not_found": "✗", "timeout": "⏱", "error": "!", "rate_limited": "⚠", "unknown": "?"}
        for r in sorted(results, key=lambda x: x["name"]):
            icon = icons.get(r["status"], "?")
            f.write(f"  [{icon}] {r['name']:<22} {r['status']:<14} {r['url']}\n")

    return fname


# ─────────────────────────────────────────────────────────────
# SCREENS
# ─────────────────────────────────────────────────────────────

def screen_search():
    console.print()
    _divider()
    console.print(f"[{LPINK}]  USERNAME SEARCH[/]")
    _divider()
    console.print()

    username = Prompt.ask(f"[{PINK}] ▶ Enter username[/]").strip()
    if not username:
        console.print(f"[{PINK}]  No username entered.[/]")
        return

    console.print()

    # ── Platform filter ──────────────────────────────────────
    t = Text()
    t.append("  [1]", style=PINK + " bold"); t.append("  All platforms  ", style=WHITE)
    t.append(f"[dim]({len(PLATFORMS)} total)[/]\n", style="")
    for i, cat in enumerate(CATEGORIES, 2):
        count = sum(1 for p in PLATFORMS if p["category"] == cat)
        t.append(f"  [{i}]", style=PINK + " bold")
        t.append(f"  {cat} only  ", style=WHITE)
        t.append(f"[dim]({count} platforms)[/]\n", style="")
    t.append(f"  [{len(CATEGORIES)+2}]", style=PINK + " bold")
    t.append("  Custom pick", style=WHITE)

    console.print(Panel(t, title=f"[{PINK}] PLATFORM FILTER [/]", border_style=PINK, padding=(0, 4)))

    choice = Prompt.ask(f"[{PINK}] ▶ Choice[/]", default="1").strip()

    try:
        n = int(choice)
    except ValueError:
        n = 1

    if n == 1:
        platforms = PLATFORMS
    elif 2 <= n <= len(CATEGORIES) + 1:
        cat = CATEGORIES[n - 2]
        platforms = [p for p in PLATFORMS if p["category"] == cat]
    else:
        # Custom pick
        console.print()
        for i, p in enumerate(PLATFORMS, 1):
            console.print(f"  [{PINK}]{i:2}[/] {p['name']:<22} [{DIM}]{p['category']}[/]")
        console.print()
        sel = Prompt.ask(f"[{PINK}] ▶ Enter numbers separated by commas (e.g. 1,3,5)[/]").strip()
        try:
            indices = [int(x.strip()) - 1 for x in sel.split(",")]
            platforms = [PLATFORMS[i] for i in indices if 0 <= i < len(PLATFORMS)]
            if not platforms:
                raise ValueError
        except (ValueError, IndexError):
            console.print(f"[{DIM}]  Invalid — using all platforms.[/]")
            platforms = PLATFORMS

    console.print()

    # ── Scan ─────────────────────────────────────────────────
    results = run_scan(username, platforms)
    found   = display_results(username, results)

    # ── Export ───────────────────────────────────────────────
    if found and Confirm.ask(f"[{PINK}] ▶ Save report to ~/Downloads?[/]", default=True):
        fname = save_results(username, results)
        console.print(f"\n  [{LPINK}]✓ Saved →[/] [{PINK}]{fname}[/]\n")

    Prompt.ask(f"[{PINK}] Press Enter to continue[/]", default="")


def screen_platforms():
    console.clear()
    show_banner()

    table = Table(
        title=f"[{PINK}] ALL SUPPORTED PLATFORMS ({len(PLATFORMS)}) [/]",
        box=box.HEAVY_EDGE,
        border_style=PINK,
        title_style=PINK + " bold",
        header_style=LPINK + " bold",
    )
    table.add_column("#",         style="dim",              width=4)
    table.add_column("Platform",  style=LPINK + " bold",    min_width=18)
    table.add_column("Category",  style=PINK,               min_width=14)
    table.add_column("URL Pattern", style=DIM,              min_width=44)

    for i, p in enumerate(PLATFORMS, 1):
        table.add_row(
            str(i),
            p["name"],
            p["category"],
            p["url"].replace("{}", "[username]"),
        )

    console.print(table)
    console.print()
    Prompt.ask(f"[{PINK}] Press Enter to go back[/]", default="")


def screen_about():
    console.clear()
    show_banner()

    t = Text()
    t.append("  Hack The System\n",                       style=PINK + " bold")
    t.append("  OSINT Username Reconnaissance Tool\n\n",  style=LPINK)
    t.append(f"  Searches across {len(PLATFORMS)} platforms concurrently,\n",  style=WHITE)
    t.append("  including social media, tech, gaming,\n", style=WHITE)
    t.append("  and creative platforms.\n\n",             style=WHITE)
    t.append("  Results can be exported to ~/Downloads.\n\n", style=WHITE)
    t.append("  ⚠  For ethical and authorised use only.\n",   style=PINK)
    t.append("     Rate limiting and bot detection may\n",    style=DIM)
    t.append("     affect accuracy on some platforms.\n",     style=DIM)

    console.print(Panel(t, title=f"[{PINK}] ABOUT [/]", border_style=PINK, padding=(1, 4)))
    Prompt.ask(f"[{PINK}] Press Enter to go back[/]", default="")


# ─────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────

def main():
    while True:
        show_banner()
        show_menu()

        choice = Prompt.ask(f"[{PINK}] ▶ Choose option[/]", default="1").strip()

        if choice == "1":
            screen_search()
        elif choice == "2":
            screen_platforms()
        elif choice == "3":
            screen_about()
        elif choice in ("0", "q", "quit", "exit"):
            console.print()
            console.print(Align.center(f"[{PINK}] Stay curious. Stay ethical.  ✌ [/]"))
            console.print()
            break
        else:
            console.print(f"[{DIM}]  Invalid option — try again.[/]")
            time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n\n[{PINK}]  Interrupted. Goodbye! ✌[/]\n")
        sys.exit(0)
