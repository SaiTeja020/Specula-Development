import os
import pandas as pd
import json
import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='openpyxl')

d = "known_attacks"
files = [f for f in os.listdir(d) if f.endswith(".xlsx")]
files.sort()

report = {}

for f in files:
    path = os.path.join(d, f)
    xls = pd.ExcelFile(path)
    file_info = {}
    for sheet in xls.sheet_names:
        df = pd.read_excel(path, sheet_name=sheet)
        
        sheet_info = {
            "num_rows": len(df),
            "num_columns": len(df.columns),
            "columns": list(df.columns)
        }
        
        # If this is the relationships file, or a relationships sheet
        if "relationship" in f.lower() or "relationship" in sheet.lower():
            if "mapping type" in df.columns or "relationship type" in df.columns:
                rel_col = "mapping type" if "mapping type" in df.columns else "relationship type"
                if "source type" in df.columns and "target type" in df.columns:
                    grouped = df.groupby([rel_col, "source type", "target type"]).size().reset_index(name='count')
                    sheet_info["relationships"] = grouped.to_dict('records')
        
        file_info[sheet] = sheet_info
    
    report[f] = file_info

with open("known_attacks_analysis.json", "w") as out:
    json.dump(report, out, indent=2)

print("Analysis complete. Check known_attacks_analysis.json")
