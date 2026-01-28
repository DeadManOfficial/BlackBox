"""
DeadMan Intelligence Bridge
Connects Deep Scrape Data (Research) to OutlawPrompts Intelligence (DeadMan Suite)
"""

import json
import os
import time
import random
import re
import hashlib
import traceback
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any

# --- CONFIGURATION ---
DEADMAN_OUTPUT_DIR = r"D:\Projects\DeadMan_Suite\Intelligence\OutlawPrompts"
RESEARCH_DATA_DIR = r"D:\Research\Scraped_Data"

SOURCES = [
    {
        "file": "wikipedia_org_ultra.json",
        "source_name": "wikipedia_deep_research",
        "type": "biographical_intel"
    },
    {
        "file": "blackhatworld_com_ultra.json",
        "source_name": "blackhatworld_trends",
        "type": "market_intel"
    },
    {
        "file": "cheifet_archive_ultra.json",
        "source_name": "stewart_cheifet_archive",
        "type": "biographical_intel"
    },
    {
        "file": "recursive_lm_intel.json",
        "source_name": "recursive_lm_research",
        "type": "technical_intel"
    }
]

# --- INTELLIGENCE STORE (Reused Logic) ---
class IntelligenceStore:
    """Centralized intelligence storage and analysis"""

    def __init__(self):
        self.competitive_data = defaultdict(list)
        self.trend_metrics = defaultdict(int)
        self.opportunity_matrix = defaultdict(dict)
        self.performance_benchmarks = defaultdict(dict)
        self.content_gaps = []
        self.strategic_insights = []
        self.agent_feeds = defaultdict(dict)
        self.timestamp = datetime.now()
        self.session_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]

    def add_competitive_intel(self, source: str, intel_type: str, data: Any):
        """Add competitive intelligence point"""
        self.competitive_data[source].append(
            {
                "type": intel_type,
                "data": data,
                "timestamp": datetime.now(),
                "processed": False,
            }
        )

    def update_trend_metrics(self, keywords: Dict[str, int]):
        """Update trending keyword metrics"""
        for keyword, count in keywords.items():
            self.trend_metrics[keyword] += count

    def generate_agent_feeds(self):
        """Generate specialized feeds for DeadMan agents"""
        feeds = {
            "content_strategy": {
                "session_id": self.session_id,
                "timestamp": datetime.now().isoformat(),
                "source": "DeadMan Intelligence Bridge",
                "trending_topics": self._extract_trending_topics(),
                "strategic_recommendations": self._generate_strategy_recommendations(),
            },
            "research_agent": {
                "session_id": self.session_id,
                "timestamp": datetime.now().isoformat(),
                "source": "DeadMan Intelligence Bridge",
                "emerging_trends": self._extract_emerging_trends(),
                "market_intel": self._extract_market_intelligence(),
            },
            "seo_optimizer": {
                "session_id": self.session_id,
                "timestamp": datetime.now().isoformat(),
                "source": "DeadMan Intelligence Bridge",
                "high_value_keywords": self._extract_seo_keywords(),
                "optimization_opportunities": self._extract_seo_opportunities(),
            },
        }
        self.agent_feeds = feeds
        return feeds

    def _extract_trending_topics(self) -> List[Dict]:
        """Extract trending topics with confidence scores"""
        top_keywords = sorted(
            self.trend_metrics.items(), key=lambda x: x[1], reverse=True
        )[:20]
        return [
            {
                "keyword": keyword,
                "frequency": count,
                "confidence": min(count * 2, 100),
                "trend_direction": "rising" if count > 5 else "stable",
            }
            for keyword, count in top_keywords
        ]

    def _generate_strategy_recommendations(self) -> List[Dict]:
        """Generate strategic recommendations based on intelligence"""
        recommendations = []
        # Simple rule-based generation for now
        top_keywords = sorted(self.trend_metrics.items(), key=lambda x: x[1], reverse=True)[:5]
        for kw, count in top_keywords:
            recommendations.append({
                "type": "content_opportunity",
                "title": f"Deep Dive: {kw.title()}",
                "action": f"Create authority content around {kw}",
                "priority": "high" if count > 10 else "medium",
                "expected_impact": count * 5
            })
        return recommendations

    def _extract_emerging_trends(self) -> List[Dict]:
        """Extract emerging trends from data"""
        trends = []
        for keyword, frequency in self.trend_metrics.items():
            if 3 <= frequency <= 15: 
                trends.append(
                    {
                        "trend": keyword,
                        "growth_stage": "emerging",
                        "opportunity_score": frequency * 10,
                        "saturation_level": "low",
                    }
                )
        return sorted(trends, key=lambda x: x["opportunity_score"], reverse=True)[:15]

    def _extract_market_intelligence(self) -> List[Dict]:
        """Extract market intelligence from data"""
        market_intel = []
        for source, intel_points in self.competitive_data.items():
            for point in intel_points:
                if "blackhatworld" in source:
                     market_intel.append({
                         "source": source,
                         "insight": point["data"].get("title", "Unknown"),
                         "url": point["data"].get("url", ""),
                         "detected": point["timestamp"]
                     })
        return market_intel[:20]

    def _extract_seo_keywords(self) -> List[Dict]:
        """Extract SEO-relevant keywords with metrics"""
        seo_keywords = []
        for keyword, frequency in self.trend_metrics.items():
            if len(keyword) > 4 and frequency > 2:
                seo_keywords.append(
                    {
                        "keyword": keyword,
                        "search_volume_indicator": frequency * 20,
                        "competition_level": "medium",
                        "content_opportunity": frequency * 15,
                    }
                )
        return sorted(seo_keywords, key=lambda x: x["content_opportunity"], reverse=True)[:30]

    def _extract_seo_opportunities(self) -> List[Dict]:
        """Extract SEO optimization opportunities"""
        opportunities = []
        high_value_keywords = [k for k, v in self.trend_metrics.items() if v > 5]
        for keyword in high_value_keywords:
            opportunities.append(
                {
                    "type": "keyword_gap",
                    "keyword": keyword,
                    "potential_traffic": self.trend_metrics[keyword] * 100,
                    "difficulty": "medium",
                    "recommendation": f"Target '{keyword}' in next content sprint",
                }
            )
        return opportunities[:10]


# --- BRIDGE MANAGER ---
class IntelligenceBridge:
    def __init__(self):
        self.store = IntelligenceStore()
        self.setup_directories()

    def setup_directories(self):
        directories = [
            DEADMAN_OUTPUT_DIR,
            f"{DEADMAN_OUTPUT_DIR}/feeds",
            f"{DEADMAN_OUTPUT_DIR}/analysis",
            f"{DEADMAN_OUTPUT_DIR}/reports",
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def ingest_data(self):
        print("[*] Starting Data Ingestion...")
        
        for source_config in SOURCES:
            file_path = os.path.join(RESEARCH_DATA_DIR, source_config["file"])
            if not os.path.exists(file_path):
                print(f"[!] File not found: {file_path}")
                continue
            
            print(f"[+] Reading {source_config['file']}...")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.process_items(data, source_config["source_name"], source_config["type"])
                print(f"    -> Ingested {len(data)} items from {source_config['source_name']}")
                
            except Exception as e:
                print(f"[!] Error processing {file_path}:")
                traceback.print_exc()

    def process_items(self, items: List[Dict], source_name: str, intel_type: str):
        for item in items:
            # 1. Add to competitive data
            self.store.add_competitive_intel(source_name, intel_type, item)
            
            # 2. Extract Keywords for Trends
            text_to_analyze = f"{item.get('title', '')} {item.get('preview', '')}"
            keywords = self.extract_keywords(text_to_analyze)
            
            # Filter common stop words
            filtered_keywords = {k: v for k, v in keywords.items() if len(k) > 3}
            self.store.update_trend_metrics(filtered_keywords)

    def extract_keywords(self, text: str) -> Dict[str, int]:
        # CLEANING - Simplified Regex
        try:
            # Remove Wikipedia JS noise (match everything after "(function")
            if "(function" in text:
                text = text.split("(function")[0]
            
            # Remove BlackHatWorld JS noise (match everything after "XF.ready")
            if "XF.ready" in text:
                text = text.split("XF.ready")[0]
            
        except Exception:
            pass # Keep original text if split fails (shouldn't happen)
        
        # Basic extraction
        words = re.findall(r"\b[a-zA-Z]{4,}\b", text.lower())
        # Filter out common junk
        stop_words = {
            'this', 'that', 'with', 'from', 'have', 'http', 'https', 'wikipedia', 'blackhatworld', 
            'ready', 'config', 'user', 'push', 'cookie', 'csrf', 'time', 'public', 'less', 'about', 
            'contact', 'login', 'register', 'forum', 'posts', 'thread', 'search', 'help', 'home',
            'news', 'media', 'members', 'share', 'posted', 'joined', 'likes', 'points', 'location'
        }
        clean_words = [w for w in words if w not in stop_words]
        return Counter(clean_words)

    def generate_outputs(self):
        print("[*] Generating Intelligence Feeds...")
        feeds = self.store.generate_agent_feeds()
        
        # Save Feeds
        for agent_name, feed_data in feeds.items():
            feed_path = f"{DEADMAN_OUTPUT_DIR}/feeds/{agent_name}_intelligence.json"
            with open(feed_path, "w", encoding="utf-8") as f:
                json.dump(feed_data, f, indent=2, default=str)
            print(f"    [+] Saved {agent_name} feed")

        # Generate Report
        print("\n[*] Generating Executive Report...")
        report = {
            "executive_summary": {
                "session_id": self.store.session_id,
                "analysis_date": datetime.now().isoformat(),
                "source": "Deep Research Bridge (Wikipedia + BlackHatWorld + RLMs)",
                "intelligence_points": sum(len(p) for p in self.store.competitive_data.values()),
                "trends_identified": len(self.store.trend_metrics),
                "deadman_feeds_generated": len(feeds)
            },
            "top_trends": [k for k, v in sorted(self.store.trend_metrics.items(), key=lambda x: x[1], reverse=True)[:15]]
        }
        
        report_path = f"{DEADMAN_OUTPUT_DIR}/reports/deadman_bridge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            
        # Markdown Summary
        md_path = f"{DEADMAN_OUTPUT_DIR}/reports/executive_summary_{datetime.now().strftime('%Y%m%d')}_BRIDGE.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# DeadMan Intelligence Bridge Report\n\n")
            f.write(f"**Session:** {self.store.session_id}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"**Intel Points:** {report['executive_summary']['intelligence_points']}\n")
            f.write(f"**Trends Found:** {report['executive_summary']['trends_identified']}\n\n")
            f.write("## Top 15 Detected Trends\n")
            for trend in report["top_trends"]:
                f.write(f"- {trend.title()}\n")
                
        print(f"    [+] Saved comprehensive report to {report_path}")
        print(f"    [+] Saved markdown summary to {md_path}")

def run_bridge():
    bridge = IntelligenceBridge()
    bridge.ingest_data()
    bridge.generate_outputs()
    print("\n[+] Bridge Operation Complete.")

if __name__ == "__main__":
    run_bridge()
