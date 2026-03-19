"""
Deterministic service-to-exploit mapping for known vulnerable services.

Runs BEFORE RAG queries to give the planner high-confidence exploit candidates
based on exact service name + version matching from recon findings.
"""

import re

SERVICE_EXPLOIT_MAP = [
    {
        "service_pattern": r"vsftpd 2\.3\.4",
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "default_payload": "cmd/unix/interact",
        "required_options": {},
        "confidence": "high",
        "notes": "Backdoor in vsftpd 2.3.4, triggers on ':)' in username. Near-guaranteed shell."
    },
    {
        "service_pattern": r"UnrealIRCd",
        "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "default_payload": "cmd/unix/reverse_perl",
        "required_options": {},
        "confidence": "high",
        "notes": "Backdoor in UnrealIRCd 3.2.8.1, near-guaranteed shell."
    },
    {
        "service_pattern": r"ProFTPD 1\.3\.5",
        "module": "exploit/unix/ftp/proftpd_modcopy_exec",
        "default_payload": "cmd/unix/reverse_perl",
        "required_options": {"SITEPATH": "/var/www", "TARGETURI": "/"},
        "confidence": "high",
        "notes": "mod_copy CPFR/CPTO to write PHP shell. Needs writable web dir."
    },
    {
        "service_pattern": r"distccd",
        "module": "exploit/unix/misc/distcc_exec",
        "default_payload": "cmd/unix/reverse_perl",
        "required_options": {},
        "confidence": "high",
        "notes": "distcc daemon allows arbitrary command execution."
    },
    {
        "service_pattern": r"[Dd]rupal",
        "module": "exploit/unix/webapp/drupal_drupalgeddon2",
        "default_payload": "php/meterpreter/reverse_tcp",
        "required_options": {},
        "confidence": "high",
        "notes": "Drupalgeddon2 RCE (CVE-2018-7600). Works on Drupal 7.x < 7.58 and 8.x < 8.5.1."
    },
    {
        "service_pattern": r"Samba (3\.[0-5]|4\.[0-5])",
        "module": "exploit/linux/samba/is_known_pipename",
        "default_payload": "cmd/unix/interact",
        "required_options": {"SMB_FOLDER": "/tmp"},
        "confidence": "medium",
        "notes": "Samba is_known_pipename (CVE-2017-7494). Needs writable share."
    },
    {
        "service_pattern": r"Apache Tomcat",
        "module": "exploit/multi/http/tomcat_mgr_upload",
        "default_payload": "java/meterpreter/reverse_tcp",
        "required_options": {"HttpUsername": "tomcat", "HttpPassword": "tomcat"},
        "confidence": "medium",
        "notes": "Tomcat manager upload. Requires valid manager credentials (try defaults)."
    },
    {
        "service_pattern": r"OpenSSH.*(5\.|6\.)",
        "module": None,
        "default_payload": None,
        "required_options": {},
        "confidence": "low",
        "notes": "Old OpenSSH — brute force or key-based attacks only. No reliable RCE module."
    },
    {
        "service_pattern": r"Apache (2\.4\.[0-9]$|2\.4\.[1-4][0-9])",
        "module": None,
        "default_payload": None,
        "required_options": {},
        "confidence": "low",
        "notes": "Apache httpd — check for web applications (Drupal, WordPress, etc.) before trying httpd exploits."
    },
]


def match_exploits(target_info: dict, failed_modules: list = None) -> list:
    """Match recon port/service/version data against known exploits.

    Args:
        target_info: Dict with structure {ip, os, hostname, ports: [{port, state, service, version}]}
        failed_modules: List of MSF module paths that already failed (will be excluded).

    Returns:
        List of matching exploit dicts, sorted by confidence (high first),
        each augmented with 'matched_port' and 'matched_service' keys.
    """
    if failed_modules is None:
        failed_modules = []

    failed_set = set(failed_modules)
    matches = []
    ports = target_info.get("ports", [])

    for port_info in ports:
        service = port_info.get("service", "")
        version = port_info.get("version", "")
        port_num = port_info.get("port", "")
        fingerprint = f"{service} {version}".strip()

        for entry in SERVICE_EXPLOIT_MAP:
            if re.search(entry["service_pattern"], fingerprint, re.IGNORECASE):
                # Skip already-failed modules
                if entry["module"] and entry["module"] in failed_set:
                    continue
                # Skip entries with no module (info-only)
                if entry["module"] is None:
                    continue
                match = dict(entry)
                match["matched_port"] = port_num
                match["matched_service"] = fingerprint
                matches.append(match)

    # Sort: high > medium > low
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda m: confidence_order.get(m["confidence"], 99))

    return matches
