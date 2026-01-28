#!/usr/bin/env python3
"""
Web Search Tool for NeuroSploit AI Agent
Allows AI to search the internet for information, documentation, and resources.
Uses Tavily API (designed for AI agents) with Traversaal as fallback.
"""

import os
import sys
import json
import argparse
import requests
from typing import Optional, List, Dict

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")
TRAVERSAAL_API_KEY = os.environ.get("TRAVERSAAL_API_KEY", "")

def search_tavily(query: str, max_results: int = 5) -> Optional[List[Dict]]:
    """Search using Tavily API - designed for AI agents"""
    if not TAVILY_API_KEY:
        return None
    
    try:
        response = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "max_results": max_results,
                "include_answer": True,
                "include_raw_content": False,
                "search_depth": "basic"
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            results = []
            
            # Include AI-generated answer if available
            if data.get("answer"):
                results.append({
                    "title": "AI Summary",
                    "content": data["answer"],
                    "url": ""
                })
            
            # Include search results
            for r in data.get("results", [])[:max_results]:
                results.append({
                    "title": r.get("title", ""),
                    "content": r.get("content", ""),
                    "url": r.get("url", "")
                })
            
            return results
    except Exception as e:
        print(f"Tavily error: {e}", file=sys.stderr)
    
    return None

def search_traversaal(query: str, max_results: int = 5) -> Optional[List[Dict]]:
    """Search using Traversaal Ares API"""
    if not TRAVERSAAL_API_KEY:
        return None
    
    try:
        response = requests.post(
            "https://api.traversaal.ai/v1/search",
            headers={
                "Authorization": f"Bearer {TRAVERSAAL_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "query": query,
                "max_results": max_results
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            results = []
            
            for r in data.get("results", [])[:max_results]:
                results.append({
                    "title": r.get("title", ""),
                    "content": r.get("snippet", r.get("content", "")),
                    "url": r.get("url", "")
                })
            
            return results
    except Exception as e:
        print(f"Traversaal error: {e}", file=sys.stderr)
    
    return None

def search_duckduckgo(query: str, max_results: int = 5) -> Optional[List[Dict]]:
    """Fallback: Search using DuckDuckGo Instant Answers (no API key needed)"""
    try:
        response = requests.get(
            "https://api.duckduckgo.com/",
            params={
                "q": query,
                "format": "json",
                "no_html": 1,
                "skip_disambig": 1
            },
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            results = []
            
            # Abstract (main answer)
            if data.get("Abstract"):
                results.append({
                    "title": data.get("Heading", "Summary"),
                    "content": data["Abstract"],
                    "url": data.get("AbstractURL", "")
                })
            
            # Related topics
            for topic in data.get("RelatedTopics", [])[:max_results]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append({
                        "title": topic.get("Text", "")[:50],
                        "content": topic.get("Text", ""),
                        "url": topic.get("FirstURL", "")
                    })
            
            return results if results else None
    except Exception as e:
        print(f"DuckDuckGo error: {e}", file=sys.stderr)
    
    return None

def websearch(query: str, max_results: int = 5) -> str:
    """
    Main search function - tries multiple backends
    Returns formatted string for AI consumption
    """
    results = None
    source = ""
    
    # Try Tavily first (best for AI)
    results = search_tavily(query, max_results)
    if results:
        source = "Tavily"
    
    # Fallback to Traversaal
    if not results:
        results = search_traversaal(query, max_results)
        if results:
            source = "Traversaal"
    
    # Fallback to DuckDuckGo
    if not results:
        results = search_duckduckgo(query, max_results)
        if results:
            source = "DuckDuckGo"
    
    if not results:
        return f"No search results found for: {query}"
    
    # Format results for AI
    output = f"Search Results ({source}) for: {query}\n"
    output += "=" * 60 + "\n\n"
    
    for i, r in enumerate(results, 1):
        output += f"[{i}] {r['title']}\n"
        if r['url']:
            output += f"    URL: {r['url']}\n"
        output += f"    {r['content'][:500]}\n\n"
    
    return output

def main():
    parser = argparse.ArgumentParser(
        description="Search the web for information",
        usage="websearch <query>"
    )
    parser.add_argument("query", nargs="+", help="Search query")
    parser.add_argument("-n", "--num-results", type=int, default=5, 
                        help="Number of results (default: 5)")
    
    args = parser.parse_args()
    query = " ".join(args.query)
    
    result = websearch(query, args.num_results)
    print(result)

if __name__ == "__main__":
    main()
