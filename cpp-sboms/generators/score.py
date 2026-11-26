import json, subprocess, sys, glob, os
Q = sys.argv[1]; files = sorted(glob.glob(os.path.join(sys.argv[2], "*.cdx.json")))
rows = []
for f in files:
    n = len(json.load(open(f)).get("components", []))
    r = {"file": os.path.basename(f), "components": n}
    for flag in ["--bsi", "--ntia"]:
        p = subprocess.run([Q, "compliance", flag, "-j", f], capture_output=True, text=True)
        try:
            d = json.loads(p.stdout); s = d["summary"]
            r[flag] = round(s["total_score"], 2)
            if flag == "--bsi":
                r["bsi_required"] = round(s["required_elements_score"], 2)
                fails = {}
                for x in d["sections"]:
                    if x.get("required") and x["score"] < 10:
                        k = f'{x["section_id"]} {x["section_title"]}'
                        fails.setdefault(k, set()).add(x["element_result"][:60])
                r["bsi_required_gaps"] = {k: sorted(v)[:3] for k, v in fails.items()}
        except Exception as e:
            r[flag] = "error: " + (p.stderr.strip().splitlines() or [str(e)])[-1][:80]
    rows.append(r)
json.dump(rows, open(sys.argv[3], "w"), indent=1)
for r in rows:
    print(f'{r["file"]:34} comps={r["components"]:>3}  BSI2.1={r.get("--bsi")}  required={r.get("bsi_required")}  NTIA={r.get("--ntia")}')
    for k, v in r.get("bsi_required_gaps", {}).items(): print("     gap:", k, v)
