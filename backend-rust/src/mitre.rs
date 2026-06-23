use serde::Serialize;
use regex::Regex;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Serialize)]
pub struct TechniqueDefinition {
    pub name: &'static str,
    pub tactic: &'static str,
    pub description: &'static str,
}

lazy_static! {
    pub static ref TECHNIQUE_DEFINITIONS: HashMap<&'static str, TechniqueDefinition> = {
        let mut m = HashMap::new();
        m.insert("T1110", TechniqueDefinition {
            name: "Brute Force",
            tactic: "Credential Access",
            description: "Adversaries may use brute force techniques to gain access to accounts.",
        });
        m.insert("T1059", TechniqueDefinition {
            name: "Command and Scripting Interpreter",
            tactic: "Execution",
            description: "Adversaries may abuse command and script interpreters to execute commands.",
        });
        m.insert("T1003", TechniqueDefinition {
            name: "OS Credential Dumping",
            tactic: "Credential Access",
            description: "Adversaries may attempt to dump credentials from the operating system.",
        });
        m.insert("T1046", TechniqueDefinition {
            name: "Network Service Discovery",
            tactic: "Discovery",
            description: "Adversaries may attempt to get a listing of services running on remote hosts.",
        });
        m.insert("T1190", TechniqueDefinition {
            name: "Exploit Public-Facing Application",
            tactic: "Initial Access",
            description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing application.",
        });
        m.insert("T1078", TechniqueDefinition {
            name: "Valid Accounts",
            tactic: "Defense Evasion",
            description: "Adversaries may use credentials of existing accounts to gain access.",
        });
        m
    };

    static ref CREDENTIAL_DUMP_RE: Vec<Regex> = vec![
        Regex::new(r"(?i)/etc/shadow").unwrap(),
        Regex::new(r"(?i)/etc/passwd").unwrap(),
        Regex::new(r"(?i)mimikatz").unwrap(),
        Regex::new(r"(?i)hashdump").unwrap(),
        Regex::new(r"(?i)secretsdump").unwrap(),
        Regex::new(r"(?i)lsass").unwrap(),
        Regex::new(r"(?i)sam\s+dump").unwrap(),
    ];

    static ref COMMAND_EXEC_RE: Vec<Regex> = vec![
        Regex::new(r"(?i)\bbash\b").unwrap(),
        Regex::new(r"(?i)\bsh\b").unwrap(),
        Regex::new(r"(?i)\bzsh\b").unwrap(),
        Regex::new(r"(?i)\bpython\b").unwrap(),
        Regex::new(r"(?i)\bperl\b").unwrap(),
        Regex::new(r"(?i)\bruby\b").unwrap(),
        Regex::new(r"(?i)\bpowershell\b").unwrap(),
        Regex::new(r"(?i)\bcmd\.exe\b").unwrap(),
        Regex::new(r"(?i)base64\s+--decode").unwrap(),
        Regex::new(r"(?i)\bexec\b").unwrap(),
        Regex::new(r"(?i)\beval\b").unwrap(),
    ];

    static ref NETWORK_SCAN_RE: Vec<Regex> = vec![
        Regex::new(r"(?i)\bnmap\b").unwrap(),
        Regex::new(r"(?i)\bnetstat\b").unwrap(),
        Regex::new(r"(?i)\bss\s+-").unwrap(),
        Regex::new(r"(?i)\bnetcat\b").unwrap(),
        Regex::new(r"(?i)\bnc\s+-").unwrap(),
        Regex::new(r"(?i)port\s*scan").unwrap(),
        Regex::new(r"(?i)\btraceroute\b").unwrap(),
    ];

    static ref EXPLOIT_RE: Vec<Regex> = vec![
        Regex::new(r"(?i)\.\.\/").unwrap(),
        Regex::new(r"(?i)<script").unwrap(),
        Regex::new(r"(?i)union\s+select").unwrap(),
        Regex::new(r"(?i)exec\s*\(").unwrap(),
        Regex::new(r"(?i)\bwget\b").unwrap(),
        Regex::new(r"(?i)\bcurl\b.*\|.*\bsh\b").unwrap(),
    ];

    static ref VALID_ACCOUNTS_USERNAMES: HashSet<&'static str> = {
        let mut s = HashSet::new();
        s.insert("root"); s.insert("admin"); s.insert("administrator"); s.insert("test"); s.insert("guest");
        s.insert("oracle"); s.insert("postgres"); s.insert("mysql"); s.insert("ftp"); s.insert("www-data");
        s
    };
}

#[derive(Serialize, Clone, Debug)]
pub struct MitreMatch {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub confidence: i32,
}

pub fn map_event(service: &str, username: &str, password: &str, command: &str, endpoint: &str, payload: &str) -> Vec<MitreMatch> {
    let mut matches = Vec::new();
    let service_upper = service.to_uppercase();
    let username_lower = username.to_lowercase();
    let combined = format!("{} {} {}", command, endpoint, payload);

    // T1110: Brute Force
    if !username.is_empty() && !password.is_empty() {
        let mut confidence = 70;
        if service_upper == "SSH" || service_upper == "FTP" || service_upper == "TELNET" || service_upper == "RDP" {
            confidence = 90;
        }
        matches.push(build_match("T1110", confidence));
    }

    // T1003: OS Credential Dumping
    if CREDENTIAL_DUMP_RE.iter().any(|re| re.is_match(&combined)) {
        matches.push(build_match("T1003", 85));
    }

    // T1059: Command and Scripting Interpreter
    if COMMAND_EXEC_RE.iter().any(|re| re.is_match(&combined)) {
        matches.push(build_match("T1059", 80));
    }

    // T1046: Network Service Discovery
    if NETWORK_SCAN_RE.iter().any(|re| re.is_match(&combined)) {
        matches.push(build_match("T1046", 75));
    }

    // T1190: Exploit Public-Facing Application
    if service_upper == "HTTP" && EXPLOIT_RE.iter().any(|re| re.is_match(&combined)) {
        matches.push(build_match("T1190", 80));
    }

    // T1078: Valid Accounts
    if VALID_ACCOUNTS_USERNAMES.contains(username_lower.as_str()) {
        matches.push(build_match("T1078", 60));
    }

    matches
}

fn build_match(technique_id: &str, confidence: i32) -> MitreMatch {
    let def = TECHNIQUE_DEFINITIONS.get(technique_id).unwrap();
    MitreMatch {
        technique_id: technique_id.to_string(),
        technique_name: def.name.to_string(),
        tactic: def.tactic.to_string(),
        confidence,
    }
}
