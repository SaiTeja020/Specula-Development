import os
import pandas as pd
from typing import Iterator
import math
import logging
from src.ingestion.indexing.threat_intel_sources import ThreatIntelRecord

logger = logging.getLogger(__name__)

class KnownAttacksExcelFetcher:
    """
    Reads the MITRE ATT&CK Excel master workbook from known_attacks/ 
    and yields enriched ThreatIntelRecord objects for Techniques.
    """
    
    def __init__(self, excel_path: str = "known_attacks/enterprise-attack-v19.2.xlsx"):
        self.excel_path = os.path.abspath(excel_path)
    
    def fetch_and_parse(self) -> Iterator[ThreatIntelRecord]:
        logger.info(f"Loading known attacks from {self.excel_path}")
        
        # Load sheets
        xls = pd.ExcelFile(self.excel_path)
        
        # We need techniques, relationships
        df_tech = pd.read_excel(xls, sheet_name="techniques")
        df_rel = pd.read_excel(xls, sheet_name="relationships")
        
        # Build relationship index
        # We want to know for each technique, which groups, software, campaigns use it,
        # and which detection strategies detect it.
        # According to analysis, Target Type is usually 'technique' for these relationships:
        # source_type -> mapping_type -> target_type
        # campaign -> uses -> technique
        # group -> uses -> technique
        # software -> uses -> technique
        # detectionstrategy -> detects -> technique
        
        used_by_group = {}
        used_by_software = {}
        used_by_campaign = {}
        detected_by = {}
        
        # Iterate relationships
        for _, row in df_rel.iterrows():
            target_id = str(row.get("target ID", ""))
            mapping_type = str(row.get("mapping type", ""))
            source_type = str(row.get("source type", ""))
            source_name = str(row.get("source name", ""))
            
            if pd.isna(source_name) or source_name == "nan":
                continue
                
            if mapping_type == "uses" and source_type == "group":
                used_by_group.setdefault(target_id, []).append(source_name)
            elif mapping_type == "uses" and source_type == "software":
                used_by_software.setdefault(target_id, []).append(source_name)
            elif mapping_type == "uses" and source_type == "campaign":
                used_by_campaign.setdefault(target_id, []).append(source_name)
            elif mapping_type == "detects" and source_type == "detectionstrategy":
                detected_by.setdefault(target_id, []).append(source_name)
                
        # Now iterate techniques and yield enriched records
        for _, row in df_tech.iterrows():
            tech_id = str(row.get("ID", ""))
            if not tech_id or pd.isna(tech_id) or tech_id == "nan":
                continue
                
            name = str(row.get("name", ""))
            desc = str(row.get("description", ""))
            if pd.isna(desc) or desc == "nan":
                desc = ""
                
            tactics = str(row.get("tactics", ""))
            tactic_list = [t.strip() for t in tactics.split(",")] if tactics and tactics != "nan" else []
            
            platforms = str(row.get("platforms", ""))
            platform_list = [p.strip() for p in platforms.split(",")] if platforms and platforms != "nan" else []
            
            is_sub = str(row.get("is sub-technique", ""))
            is_sub_bool = is_sub.strip().lower() == "true"
            
            parent_id = str(row.get("sub-technique of", ""))
            if pd.isna(parent_id) or parent_id == "nan":
                parent_id = None
                
            stix = str(row.get("STIX ID", ""))
            created = str(row.get("created", ""))
            last_mod = str(row.get("last modified", ""))
            url = str(row.get("url", ""))
            version = str(row.get("version", ""))
            
            # Retrieve enriched arrays
            groups = used_by_group.get(tech_id, [])
            software = used_by_software.get(tech_id, [])
            campaigns = used_by_campaign.get(tech_id, [])
            detections = detected_by.get(tech_id, [])
            
            # Construct embedded text
            embed_parts = [
                f"Technique: {tech_id} - {name}",
                f"Tactics: {', '.join(tactic_list)}" if tactic_list else "",
                f"Platforms: {', '.join(platform_list)}" if platform_list else "",
                f"Description: {desc}" if desc else ""
            ]
            
            if groups:
                embed_parts.append(f"Used by Groups: {', '.join(groups)}")
            if software:
                embed_parts.append(f"Used by Software: {', '.join(software)}")
            if campaigns:
                embed_parts.append(f"Used by Campaigns: {', '.join(campaigns)}")
            if detections:
                embed_parts.append(f"Detection Strategies: {', '.join(detections)}")
                
            embed_text = "\n".join([p for p in embed_parts if p])
            
            yield ThreatIntelRecord(
                record_id=tech_id,
                record_type="attack_technique",
                title=name,
                embed_text=embed_text,
                source="mitre_attack_excel",
                source_version=version if version and version != "nan" else "19.2",
                tags=tactic_list,
                stix_id=stix if stix and stix != "nan" else None,
                platforms=platform_list,
                is_subtechnique=is_sub_bool,
                parent_technique_id=parent_id,
                created=created if created and created != "nan" else None,
                last_modified=last_mod if last_mod and last_mod != "nan" else None,
                url=url if url and url != "nan" else None
            )
