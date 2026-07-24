"""Deliberately vulnerable sample app for testing Aegis-generated scanners."""
import subprocess

# Hardcoded secret — Gitleaks / Trivy secret scan should flag this.
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE0000wJalrXUtnFEMI/K7MDENG"

def run(user_input: str):
    # eval on untrusted input — Bandit B307 / Semgrep should flag this.
    return eval(user_input)

def ping(host: str):
    # shell=True with interpolation — command injection, Bandit B602.
    return subprocess.check_output("ping -c1 " + host, shell=True)