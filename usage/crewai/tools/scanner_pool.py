#!/usr/bin/env python3
"""
Scanner Pool — download & manage external security scanners.

Supports on-demand installation of tools like semgrep, trivy, grype,
syft, nuclei, kubescape, and others. Exposes them as CrewAI-compatible
custom tools that can be assigned to agents.
"""

import os
import sys
import json
import shutil
import logging
import subprocess
import tempfile
import zipfile
import tarfile
import platform
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request

logger = logging.getLogger("ScannerPool")


# ---------------------------------------------------------------------------
# Scanner registry — known tools with install strategies
# ---------------------------------------------------------------------------

SCANNER_REGISTRY = {
    "semgrep": {
        "description": "Static analysis for multi-language codebases",
        "install_command": "pip install semgrep",
        "verify_command": "semgrep --version",
        "run_template": "semgrep --config={ruleset} --json -o {output} {target}",
        "category": "sast",
        "ruleset": "p/default",
    },
    "trivy": {
        "description": "Unified scanner for container images, fs, repos, configs",
        "install_script": {
            "linux": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
            "darwin": "brew install aquasecurity/trivy/trivy",
        },
        "install_command": "which trivy || (brew install aquasecurity/trivy/trivy 2>/dev/null || curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin)",
        "verify_command": "trivy --version",
        "run_template": "trivy fs --format json --output {output} {target}",
        "category": "sca",
    },
    "grype": {
        "description": "Vulnerability scanner for container images and filesystems",
        "install_command": "which grype || (curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin)",
        "verify_command": "grype version",
        "run_template": "grype {target} -o json --file {output}",
        "category": "sca",
    },
    "syft": {
        "description": "SBOM generation tool (CycloneDX, SPDX)",
        "install_command": "which syft || (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin)",
        "verify_command": "syft version",
        "run_template": "syft {target} -o cyclonedx-json --file {output}",
        "category": "sbom",
    },
    "nuclei": {
        "description": "Fast vulnerability scanner based on YAML templates",
        "install_command": "which nuclei || (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)",
        "verify_command": "nuclei -version",
        "run_template": "nuclei -target {target} -json -o {output}",
        "category": "dast",
    },
    "kubescape": {
        "description": "Kubernetes security scanning (CIS, NSA, MITRE)",
        "install_command": "which kubescape || (curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash)",
        "verify_command": "kubescape version",
        "run_template": "kubescape scan {target} --format json --output {output}",
        "category": "config",
    },
    "checkov": {
        "description": "IaC security scanner (Terraform, CloudFormation, K8s, Docker)",
        "install_command": "pip install checkov",
        "verify_command": "checkov --version",
        "run_template": "checkov --directory {target} --compact --output json --output-file-path {output}",
        "category": "config",
    },
    "tfsec": {
        "description": "Terraform security scanner",
        "install_command": "which tfsec || (curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install.sh | sh)",
        "verify_command": "tfsec --version",
        "run_template": "tfsec {target} --format json --out {output}",
        "category": "config",
    },
    "kics": {
        "description": "Infrastructure as Code security scanner",
        "install_command": "which kics || (curl -sfL 'https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh' | sh)",
        "verify_command": "kics version",
        "run_template": "kics scan --path {target} --output-path {output} --output-name results --report-formats json",
        "category": "config",
    },
    "bearer": {
        "description": "SAST for sensitive data flows, secrets, and compliance",
        "install_command": "which bearer || (curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh)",
        "verify_command": "bearer version",
        "run_template": "bearer scan {target} --format json --output {output}",
        "category": "sast",
    },
    "sonarqube_scanner": {
        "description": "SonarQube CLI scanner for code quality & security",
        "install_command": "which sonar-scanner || (curl -sL https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip -o /tmp/sonar.zip && unzip -q /tmp/sonar.zip -d /opt && ln -sf /opt/sonar-scanner-*/bin/sonar-scanner /usr/local/bin/)",
        "verify_command": "sonar-scanner --version",
        "run_template": "sonar-scanner -Dsonar.sources={target} -Dsonar.host.url={host} -Dsonar.login={token}",
        "category": "sast",
        "requires_auth": True,
    },
}


class ScannerTool:
    """
    Represents an installed scanner tool that agents can use.

    Usage:
        tool = ScannerTool("semgrep")
        result = tool.run(target="/project/src")
    """

    def __init__(self, name: str, registry: Optional[dict] = None):
        self.name = name
        self.registry = registry or SCANNER_REGISTRY
        self.meta = self.registry.get(name)
        if not self.meta:
            raise ValueError(f"Unknown scanner: {name}. Available: {list(self.registry.keys())}")
        self._ensure_installed()

    def _ensure_installed(self) -> bool:
        """Install scanner if not already available."""
        if self.is_available():
            logger.info(f"Scanner '{self.name}' already installed")
            return True

        install_cmd = self.meta.get("install_command")
        if not install_cmd:
            logger.warning(f"No install command for '{self.name}'")
            return False

        logger.info(f"Installing scanner '{self.name}'...")
        try:
            result = subprocess.run(
                install_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.warning(f"Install of '{self.name}' failed: {result.stderr.strip()}")
                return False
            logger.info(f"Scanner '{self.name}' installed successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Install of '{self.name}' timed out")
            return False
        except Exception as e:
            logger.warning(f"Install of '{self.name}' error: {e}")
            return False

    def is_available(self) -> bool:
        """Check if scanner binary exists."""
        verify = self.meta.get("verify_command")
        if not verify:
            # Try just which/where
            binary_name = self.name.split("/")[0]
            return shutil.which(binary_name) is not None
        try:
            result = subprocess.run(
                verify, shell=True, capture_output=True, text=True, timeout=30
            )
            return result.returncode == 0
        except Exception:
            return False

    def run(
        self,
        target: str,
        output_dir: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> dict:
        """
        Run the scanner against a target.

        Args:
            target: Path or URL to scan
            output_dir: Directory for output files (default: temp dir)
            extra_args: Additional CLI arguments

        Returns:
            dict with keys: success, output_file, stdout, stderr, returncode
        """
        if not self.is_available():
            self._ensure_installed()
            if not self.is_available():
                return {"success": False, "error": f"Scanner '{self.name}' not available"}

        output_dir = output_dir or tempfile.mkdtemp(prefix=f"{self.name}_")
        output_file = os.path.join(output_dir, f"{self.name}_results.json")

        template = self.meta.get("run_template", "")
        if not template:
            return {"success": False, "error": f"No run template for '{self.name}'"}

        command = template.format(
            target=target,
            output=output_file,
            ruleset=self.meta.get("ruleset", "p/default"),
        )
        if extra_args:
            command += f" {extra_args}"

        logger.info(f"Running: {command}")
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=600
            )
            return {
                "success": result.returncode == 0,
                "output_file": output_file,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:2000],
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scanner timed out (600s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def __repr__(self) -> str:
        return f"ScannerTool(name='{self.name}', available={self.is_available()})"


class ScannerPool:
    """
    Pool of on-demand scanner tools, configured from YAML.

    Usage:
        pool = ScannerPool(config["tools"])
        pool.ensure_all()
        result = pool.run("semgrep", target="/project/src")
    """

    def __init__(self, tools_config: Optional[dict] = None):
        self.tools_config = tools_config or {}
        self.instances: dict[str, ScannerTool] = {}

    def ensure(self, name: str) -> Optional[ScannerTool]:
        """Ensure a single scanner is installed and return it."""
        if name not in self.instances:
            try:
                self.instances[name] = ScannerTool(name)
            except ValueError as e:
                logger.error(f"Cannot create scanner '{name}': {e}")
                return None
        return self.instances[name]

    def ensure_all(self) -> list[str]:
        """Install all configured scanners. Returns list of available names."""
        enabled = self.tools_config.get("enabled", [])
        available = []
        for name in enabled:
            tool = self.ensure(name)
            if tool and tool.is_available():
                available.append(name)
        return available

    def run(
        self,
        name: str,
        target: str,
        output_dir: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> dict:
        """Run a scanner by name."""
        tool = self.ensure(name)
        if not tool:
            return {"success": False, "error": f"Scanner '{name}' unknown"}
        return tool.run(target, output_dir, extra_args)

    def get_results_dir(self, name: str, base_dir: str = "/output/tools") -> str:
        """Get the results output directory for a scanner."""
        path = os.path.join(base_dir, name)
        os.makedirs(path, exist_ok=True)
        return path


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def ensure_scanner(name: str) -> Optional[ScannerTool]:
    """Quick one-off: ensure a scanner is available."""
    try:
        tool = ScannerTool(name)
        return tool if tool.is_available() else None
    except (ValueError, Exception) as e:
        logger.warning(f"ensure_scanner('{name}'): {e}")
        return None


def get_available_scanners() -> list[str]:
    """List all scanners currently available on the system."""
    available = []
    for name in SCANNER_REGISTRY:
        try:
            tool = ScannerTool(name)
            if tool.is_available():
                available.append(name)
        except (ValueError, Exception):
            continue
    return available


def run_scanner(
    name: str,
    target: str,
    output_dir: Optional[str] = None,
    extra_args: Optional[str] = None,
) -> dict:
    """Quick one-off: run a scanner."""
    tool = ensure_scanner(name)
    if not tool:
        return {"success": False, "error": f"Cannot use scanner '{name}'"}
    return tool.run(target, output_dir, extra_args)