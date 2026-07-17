"""
Attack Chaining Engine.

Detects multi-step exploit chains, including multi-hop paths:
- e.g. SQL Injection (produces admin_credentials) -> Broken Access Control (requires admin_credentials, produces admin_panel_access) -> Command Injection (requires admin_panel_access, produces system_shell_access).
"""

def find_chains(findings: list[dict]) -> list[dict]:
    chains = []
    
    # 1. Detect 1-hop chains (A -> B)
    for source in findings:
        for target in findings:
            if source is target:
                continue
            shared = set(source.get("produces", [])) & set(target.get("requires", []))
            if shared:
                chains.append({
                    "from": source["type"],
                    "to": target["type"],
                    "via": sorted(list(shared)),
                    "path": [source["type"], target["type"]],
                    "description": (
                        f"{source['type']} on {source['endpoint']} produces "
                        f"{', '.join(sorted(shared))}, which satisfies what "
                        f"{target['type']} on {target['endpoint']} needs — "
                        f"chained together this is an exploit path."
                    )
                })

    # 2. Detect 2-hop chains (A -> B -> C)
    multi_hop_chains = []
    for c1 in chains:
        for c2 in chains:
            if c1["to"] == c2["from"] and c1["from"] != c2["to"] and c1["from"] != c2["from"]:
                # Found a path A -> B -> C
                via_combined = sorted(list(set(c1["via"] + c2["via"])))
                path_nodes = c1["path"] + [c2["to"]]
                multi_hop_chains.append({
                    "from": c1["from"],
                    "to": c2["to"],
                    "via": via_combined,
                    "path": path_nodes,
                    "description": (
                        f"🔥 Multi-Hop Chain Detected: {c1['from']} -> {c1['to']} -> {c2['to']}. "
                        f"Initial exploit produces {', '.join(c1['via'])}, granting entry to "
                        f"{c1['to']}, which yields {', '.join(c2['via'])} to execute {c2['to']}."
                    )
                })
    
    # Return both 1-hop and multi-hop chains, with multi-hops ordered first
    return multi_hop_chains + chains


def mark_chained_findings(findings: list[dict], chains: list[dict]) -> None:
    """
    Mutates findings in place, setting finding["chained"] = True for any
    finding that participates in at least one chain.
    """
    chained_types = set()
    for c in chains:
        # Some chains are lists or dict nodes
        if "path" in c:
            for node in c["path"]:
                chained_types.add(node)
        else:
            chained_types.add(c["from"])
            chained_types.add(c["to"])

    for f in findings:
        f["chained"] = f["type"] in chained_types
