import re
import pickle
import nmap
import json
import hashlib
import requests
# ------------------------------
# Load NLP Model + Data
# ------------------------------
with open("data/nlp_model.pkl", "rb") as f:
    vectorizer, model, data = pickle.load(f)

print(" Chatbot ready! Type 'exit' to quit.\n")

# ------------------------------
# Extract target (IP/Domain)
# ------------------------------
def extract_target(text):
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    domain_match = re.search(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

    if ip_match:
        return ip_match.group()
    elif domain_match:
        return domain_match.group()
    return None

# ------------------------------
# Execute Nmap Scan
# ------------------------------
import nmap

def execute_nmap(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-T4 -F")

        if target not in nm.all_hosts():
            return " No results returned by Nmap."

        result = []
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                state = nm[target][proto][port]['state']
                if state == "open":
                    result.append(f"Port {port}/{proto} → OPEN")

        if not result:
            return " No open ports found."

        return "\n".join(result)

    except Exception as e:
        return f" Error running Nmap: {e}"

import subprocess

def execute_ping(target):
    try:
        result = subprocess.run(
            ["ping", "-n", "4", target],  
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error running ping: {e}"

def execute_whois(target):
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error running whois: {e}"

def execute_nslookup(target):
    try:
        result = subprocess.run(
            ["nslookup", target],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error running nslookup: {e}"

def execute_traceroute(target):
    try:
        result = subprocess.run(
            ["tracert", target],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error running traceroute: {e}"

def execute_subnet_scan(subnet):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn")
        hosts = nm.all_hosts()

        if not hosts:
            return "No active devices found."

        return "\n".join([f"Active: {h}" for h in hosts])

    except Exception as e:
        return f"Error running subnet scan: {e}"
def execute_malware_scan(path):
    try:
        result = subprocess.run(
            ["powershell", "-Command", f"Start-MpScan -ScanPath '{path}'"],
            capture_output=True,
            text=True
        )
        return result.stdout or "Scan completed."
    except Exception as e:
        return f"Error running malware scan: {e}"

# ------------------------------
# Detect Intent
# ------------------------------
def detect_intent(user_input):
    user_input_low = user_input.lower()

    # ---------------------------
    # 1) KEYWORD-BASED INTENT BOOST
    # ---------------------------
    keyword_intents = {
        "ping": ["ping", "icmp", "latency", "reachable"],
        "whois": ["whois", "ownership", "registrar", "domain info"],
        "nslookup": ["nslookup", "resolve", "dns", "ip of", "a record"],
        "traceroute": ["traceroute", "trace", "hops", "path"],
        "nmap": ["nmap", "scan", "ports", "service detection"],
        "subnet_scan": ["subnet", "network scan", "range scan", "/24"],
        "malware_scan": ["malware", "virus", "scan file", "check file"],
    }

    keyword_score = {}

    for intent, words in keyword_intents.items():
        keyword_score[intent] = sum(w in user_input_low for w in words)

    # Highest keyword match
    keyword_best = max(keyword_score, key=keyword_score.get)
    keyword_value = keyword_score[keyword_best]

    # ---------------------------
    # 2) NLP MODEL PREDICTION
    # ---------------------------
    X = vectorizer.transform([user_input])
    proba = model.predict_proba(X)[0]
    nlp_best = model.classes_[proba.argmax()]
    nlp_value = proba.max()

    # ---------------------------
    # 3) DECISION LOGIC (SMART HYBRID)
    # ---------------------------

    # If keyword score high → trust keywords
    if keyword_value >= 2:
        final_intent = keyword_best
    # If NLP very confident → use NLP
    elif nlp_value >= 0.60:
        final_intent = nlp_best
    # If unsure → fallback to keyword
    else:
        final_intent = keyword_best

    # ---------------------------
    # 4) TARGET EXTRACTION (IP/domain/subnet/path)
    # ---------------------------
    import re

    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){1,3}\b", user_input)
    domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", user_input)
    subnet_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", user_input)
    path_match = re.search(r"[A-Za-z]:\\[^\n]*", user_input)

    target = None
    if subnet_match:
        target = subnet_match.group()
    elif ip_match:
        target = ip_match.group()
    elif domain_match:
        target = domain_match.group()
    elif path_match:
        target = path_match.group()

    return final_intent, target

# ------------------------------
# Handle Intents
# ------------------------------
def handle_input(user_input):
    intent, target = detect_intent(user_input)
    print(f"[DEBUG] Intent: {intent}, Target: {target}")

    if intent == "nmap":
        return execute_nmap(target) if target else "Please provide an IP/domain name."

    if intent == "ping":
        return execute_ping(target) if target else "Please provide an IP/domain."

    if intent == "whois":
        return execute_whois(target) if target else "Please provide a domain."

    if intent == "traceroute":
        return execute_traceroute(target) if target else "Please provide an IP/domain."

    if intent == "nslookup":
        return execute_nslookup(target) if target else "Please provide an IP/domain."

    if intent == "subnet_scan":
        return execute_subnet_scan(target) if target else "Provide subnet like: 192.168.1.0/24"

    if intent == "malware_scan":
        return execute_malware_scan(target) if target else "Provide a file path."

    return "I didn't understand your request."


# ------------------------------
# Chat Loop
# ------------------------------
while True:
    user_input = input("You: ")

    if user_input.lower() in ["exit", "quit"]:
        print("Goodbye!")
        break

    response = handle_input(user_input)
    print("Bot:", response)
