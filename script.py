import requests
from bs4 import BeautifulSoup
import json
import os
import datetime
import subprocess

DATABASE_FILE = "database.json"
CATEGORIES_DIR = "categories"
README_FILE = "README.md"

CATEGORIES = {
    "XSS": ["xss", "cross-site scripting", "cross site scripting", "xs-search", "xsleaks"],
    "IDOR": ["idor", "insecure direct object reference", "unauthorized access", "bola", "broken object level authorization"],
    "SSRF": ["ssrf", "server-side request forgery", "server side request forgery"],
    "RCE": ["rce", "remote code execution", "command injection", "remote code execution"],
    "Open Redirect": ["open redirect", "url redirection", "unvalidated redirect"],
    "CSRF": ["csrf", "cross-site request forgery", "cross site request forgery"],
    "SQLi": ["sqli", "sql injection", "blind sql injection", "sql-injection"],
    "Other": []
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
}

def load_database():
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_database(db):
    with open(DATABASE_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4)

def categorize_report(title):
    title_lower = title.lower()
    for cat, keywords in CATEGORIES.items():
        if cat == "Other":
            continue
        for kw in keywords:
            if kw in title_lower:
                return cat
    return "Other"

def fetch_hackerone_reports():
    # Attempting to fetch HackerOne reports using their GraphQL
    # This might return empty if the API schema changed or blocked without auth token, but handles it gracefully
    url = "https://hackerone.com/graphql"
    query = """
    query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $after: String) {
      hacktivity_items(first: 25, query: $querystring, order_by: $orderBy, after: $after) {
        nodes {
          ... on Disclosed {
            id
            url
            report {
              title
            }
          }
        }
      }
    }
    """
    variables = {
        "querystring": "",
        "orderBy": {"field": "popular", "direction": "DESC"}
    }
    links = []
    try:
        response = requests.post(url, headers={"User-Agent": HEADERS["User-Agent"], "Accept": "application/json"}, json={"query": query, "variables": variables}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            nodes = data.get("data", {}).get("hacktivity_items", {}).get("nodes", [])
            for node in nodes:
                title = node.get("report", {}).get("title")
                report_url = node.get("url")
                if title and report_url:
                    links.append({
                        "title": title.strip(),
                        "url": report_url,
                        "source": "HackerOne"
                    })
    except Exception as e:
        print(f"Error fetching HackerOne: {e}")
    return links

def fetch_bugcrowd_reports():
    # Fallback to Bugcrowd disclosures (graceful fail if endpoint 404s due to Bugcrowd updates)
    url = "https://bugcrowd.com/crowdcontrol/disclosures"
    links = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '/disclosures/' in href and not href.endswith('/disclosures'):
                    title = a_tag.text.strip()
                    if title:
                        full_url = "https://bugcrowd.com" + href if href.startswith('/') else href
                        links.append({
                            "title": title,
                            "url": full_url,
                            "source": "Bugcrowd"
                        })
    except Exception as e:
        print(f"Error fetching Bugcrowd: {e}")
    return links

def fetch_pentesterland_reports():
    # Using public blog writeups via pentester.land JSON endpoint for reliable robust coverage
    # (Bugcrowd uses BS4 for standard HTML extraction as per requirements)
    url = "https://pentester.land/writeups.json"
    links = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", [])
            for item in data:
                for link in item.get("Links", []):
                    title = link.get("Title", "")
                    url_str = link.get("Link", "")
                    if title and url_str:
                        links.append({
                            "title": title.strip(),
                            "url": url_str,
                            "source": "PentesterLand (Public Blogs)"
                        })
    except Exception as e:
        print(f"Error fetching PentesterLand: {e}")
    return links

def deduplicate_and_categorize(new_reports, db):
    existing_urls = {item["url"] for item in db}
    updates = 0
    for report in new_reports:
        norm_url = report["url"].rstrip('/')
        if norm_url not in existing_urls:
            report["url"] = norm_url
            report["category"] = categorize_report(report["title"])
            report["date_added"] = datetime.datetime.now().isoformat()
            db.append(report)
            existing_urls.add(norm_url)
            updates += 1
    return updates

def generate_markdown(db):
    if not os.path.exists(CATEGORIES_DIR):
        os.makedirs(CATEGORIES_DIR)
        
    category_counts = {cat: 0 for cat in CATEGORIES.keys()}
    reports_by_category = {cat: [] for cat in CATEGORIES.keys()}

    for item in db:
        cat = item.get("category", "Other")
        if cat not in reports_by_category:
            cat = "Other"
        reports_by_category[cat].append(item)
        category_counts[cat] += 1
        
    for cat in CATEGORIES.keys():
        file_path = os.path.join(CATEGORIES_DIR, f"{cat.replace(' ', '_')}.md")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"# {cat} Bug Bounty Reports\n\n")
            sorted_reports = sorted(reports_by_category[cat], key=lambda x: x.get("date_added", ""), reverse=True)
            for r in sorted_reports:
                f.write(f"* [{r['title']}]({r['url']}) - *{r['source']}*\n")
                
    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write("# Automated Bug Bounty Reports\n\n")
        f.write("A curated list of publicly disclosed bug bounty reports, automatically updated and categorized.\n\n")
        
        f.write("## Categories\n\n")
        for cat in CATEGORIES.keys():
            if category_counts[cat] > 0:
                cat_file = f"{CATEGORIES_DIR}/{cat.replace(' ', '_')}.md"
                f.write(f"* [{cat}]({cat_file}) ({category_counts[cat]} reports)\n")
                
        f.write(f"\n**Total Reports Analyzed:** {len(db)}\n")
        f.write(f"**Last Updated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

def push_to_github():
    try:
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        if not status.stdout.strip():
            print("No new updates to commit.")
            return

        print("Changes detected, committing to GitHub...")
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "commit", "-m", "Auto-update bug bounty reports"], check=True)
        # Using git push securely
        subprocess.run(["git", "push"], check=True)
        print("Successfully pushed to GitHub.")
    except Exception as e:
        print(f"Error during git operations: {e}")

def main():
    print("Starting Bug Bounty Report Collector...")
    db = load_database()
    
    print("Fetching reports from HackerOne...")
    h1_reports = fetch_hackerone_reports()
    
    print("Fetching reports from Bugcrowd...")
    bc_reports = fetch_bugcrowd_reports()
    
    print("Fetching reports from PentesterLand (Public Blogs)...")
    pl_reports = fetch_pentesterland_reports()
    
    all_new_reports = h1_reports + bc_reports + pl_reports
    
    print(f"Found {len(all_new_reports)} links in this run.")
    updates = deduplicate_and_categorize(all_new_reports, db)
    
    if updates > 0:
        print(f"Added {updates} new reports.")
        save_database(db)
        generate_markdown(db)
        push_to_github()
    else:
        print("No new reports found, ensuring base markdown exists...")
        if not os.path.exists(README_FILE):
            generate_markdown(db)

if __name__ == "__main__":
    main()
