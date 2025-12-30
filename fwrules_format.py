import re
import sys

def parse_firewall_block(block: str) -> dict:
    """Parse one registry-exported firewall rule block into a structured dict."""
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if len(lines) < 3:
        return None  # not enough data
    
    rule_id = lines[2].strip("{}")
    raw_rule = lines[3]

    parts = raw_rule.split("SZ:")[-1].split("|")
    fields = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()

    return {
        "ID": rule_id,
        "DisplayName": fields.get("Name", ""),
        "Active": str(fields.get("Active", "")).capitalize(),
        "Profile": "All",
        "Direction": "Inbound" if fields.get("Dir", "").lower() == "in" else "Outbound",
        "Action": fields.get("Action", ""),
        "AppPath": fields.get("App", ""),
        "ProgramPath": fields.get("App", ""),
        "Protocol": fields.get("Protocol", "Any"),
        "LocalPort": fields.get("LPort", "Any"),
        "RemotePort": fields.get("RPort", "Any"),
        "AMD": "ADD"
    }


def format_firewall_rule(rule: dict) -> str:
    return "\n".join([f"{k:<12}: {v}" for k, v in rule.items()])


def parse_firewall_input(text: str):
    """Split full pasted input into blocks and parse them"""
    blocks = text.strip().split("\n\n")
    rules = []
    for block in blocks:
        rule = parse_firewall_block(block)
        if rule:
            rules.append(rule)
    return rules


if __name__ == "__main__":
    # Example pasted input (simulate reading from a file or paste)
    pasted_input = """
Computer
Software\Policies\Microsoft\WindowsFirewall\FirewallRules
{04F364C3-F6C8-4FEA-A85B-9CD40E15A287}
SZ:v2.33|Action=Block|Active=TRUE|Dir=In|App=%SystemDrive%\\vw\\catia\\grc11\\sw\\1\\win_b64\\code\\bin\\CNEXT.exe|Name=[SC] FastDMU cnext.exe Block|
"""

    parsed_rules = parse_firewall_input(pasted_input)

    for rule in parsed_rules:
        print()##print("=" * 80)
        print(format_firewall_rule(rule))