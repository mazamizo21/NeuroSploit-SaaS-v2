#!/usr/bin/env python3
"""
Smart Download Tool for talon AI Agent
Helps AI find and download resources like wordlists, exploits, scripts.
Searches for download URLs and fetches them.
Tracks downloads to prevent duplicates.
"""

import os
import sys
import argparse
import requests
from typing import Optional, Tuple
from urllib.parse import urlparse

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")
DOWNLOAD_TRACKER = "/tmp/.talon_downloads"  # Track downloaded files


def get_downloaded_files() -> set:
    """Get set of already downloaded files"""
    if os.path.exists(DOWNLOAD_TRACKER):
        with open(DOWNLOAD_TRACKER, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    return set()


def mark_downloaded(resource: str, path: str):
    """Mark a resource as downloaded"""
    with open(DOWNLOAD_TRACKER, 'a') as f:
        f.write(f"{resource}:{path}\n")


def is_already_downloaded(resource: str) -> Optional[str]:
    """Check if resource already downloaded, return path if so"""
    downloaded = get_downloaded_files()
    for entry in downloaded:
        if ':' in entry:
            res, path = entry.split(':', 1)
            if res.lower() == resource.lower() and os.path.exists(path):
                return path
    return None


# Known resource URLs for common pentesting resources
KNOWN_RESOURCES = {
    "rockyou": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "rockyou.txt": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "seclists": "https://github.com/danielmiessler/SecLists/archive/master.zip",
    "common-passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "top1000-passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
}

def search_download_url(resource: str) -> Optional[str]:
    """Search for a download URL for the requested resource"""
    
    # Check known resources first
    resource_lower = resource.lower()
    for key, url in KNOWN_RESOURCES.items():
        if key in resource_lower:
            return url
    
    # Search online for download URL
    if not TAVILY_API_KEY:
        return None
    
    query = f"{resource} download url github raw"
    
    try:
        response = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "max_results": 5,
                "include_answer": False,
                "search_depth": "basic"
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Look for direct download URLs
            for r in data.get("results", []):
                url = r.get("url", "")
                # Prefer raw GitHub URLs or direct file links
                if any(x in url for x in ["raw.githubusercontent", ".txt", ".zip", ".tar", "download"]):
                    return url
            
            # Return first result URL as fallback
            if data.get("results"):
                return data["results"][0].get("url")
                
    except Exception as e:
        print(f"Search error: {e}", file=sys.stderr)
    
    return None

def download_file(url: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
    """Download a file from URL"""
    try:
        # Determine output filename
        if not output_path:
            parsed = urlparse(url)
            filename = os.path.basename(parsed.path) or "downloaded_file"
            output_path = f"/tmp/{filename}"
        
        print(f"Downloading from: {url}")
        print(f"Saving to: {output_path}")
        
        response = requests.get(url, stream=True, timeout=120)
        response.raise_for_status()
        
        # Get file size if available
        total_size = int(response.headers.get('content-length', 0))
        
        with open(output_path, 'wb') as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = (downloaded / total_size) * 100
                        print(f"\rProgress: {pct:.1f}%", end="", flush=True)
        
        print()  # New line after progress
        
        # Verify file exists and has content
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            size = os.path.getsize(output_path)
            return True, f"Downloaded successfully: {output_path} ({size} bytes)"
        else:
            return False, "Download failed: File is empty"
            
    except Exception as e:
        return False, f"Download error: {e}"

def smart_download(resource: str, output_path: Optional[str] = None) -> str:
    """
    Smart download - finds and downloads a resource.
    Can handle resource names or direct URLs.
    Prevents duplicate downloads.
    """
    # Check if already downloaded
    existing_path = is_already_downloaded(resource)
    if existing_path:
        size = os.path.getsize(existing_path)
        return f"⚠️ ALREADY DOWNLOADED: {resource}\nFile exists at: {existing_path} ({size} bytes)\nUse this file - do not download again."
    
    # Check if it's already a URL
    if resource.startswith("http://") or resource.startswith("https://"):
        url = resource
    else:
        # Search for the download URL
        print(f"Searching for download URL for: {resource}")
        url = search_download_url(resource)
        
        if not url:
            return f"Could not find download URL for: {resource}\nTry searching with: websearch \"{resource} download url\""
    
    success, message = download_file(url, output_path)
    
    # Track successful download
    if success:
        # Determine actual path
        if output_path:
            actual_path = output_path
        else:
            parsed = urlparse(url)
            filename = os.path.basename(parsed.path) or "downloaded_file"
            actual_path = f"/tmp/{filename}"
        mark_downloaded(resource, actual_path)
    
    return message

def main():
    parser = argparse.ArgumentParser(
        description="Download resources (wordlists, tools, etc.)",
        usage="download <resource_or_url> [-o output_path]"
    )
    parser.add_argument("resource", nargs="+", help="Resource name or URL to download")
    parser.add_argument("-o", "--output", help="Output file path")
    
    args = parser.parse_args()
    resource = " ".join(args.resource)
    
    result = smart_download(resource, args.output)
    print(result)

if __name__ == "__main__":
    main()
