#!/usr/bin/env python3
import json
import subprocess
from typing import Any, Dict, List

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from karton.core import Task

DEFAULT_NIKTO_TIMEOUT_SECONDS = 300
DEFAULT_NIKTO_TUNING = "123b"


def parse_nikto_output(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Nikto JSON/JSONL output while ignoring non-JSON lines."""
    findings: List[Dict[str, Any]] = []
    for line in raw_output.splitlines():
        cleaned = line.strip()
        if not cleaned or not cleaned.startswith("{"):
            continue
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict):
            vulns = data.get("vulnerabilities")
            if isinstance(vulns, list):
                for item in vulns:
                    if isinstance(item, dict):
                        findings.append(item)
            elif any(k in data for k in ("id", "msg", "url")):
                findings.append(data)
    return findings


def build_nikto_command(
    target_url: str,
    timeout_seconds: int = DEFAULT_NIKTO_TIMEOUT_SECONDS,
    tuning: str = DEFAULT_NIKTO_TUNING,
    user_agent: str | None = None,
) -> List[str]:
    """Build a bounded Nikto CLI command outputting JSON."""
    command = [
        "nikto",
        "-h",
        target_url,
        "-Format",
        "json",
        "-maxtime",
        f"{timeout_seconds}s",
        "-Tuning",
        tuning,
    ]
    if user_agent:
        command.extend(["-useragent", user_agent])
    return command


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class Nikto(ArtemisBase):  # type: ignore
    """Runs Nikto web server checks on HTTP services."""

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "nikto"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _scan_url(self, target_url: str) -> List[Dict[str, Any]]:
        user_agent = Config.Miscellaneous.CUSTOM_USER_AGENT or None
        command = build_nikto_command(
            target_url=target_url,
            timeout_seconds=DEFAULT_NIKTO_TIMEOUT_SECONDS,
            tuning=DEFAULT_NIKTO_TUNING,
            user_agent=user_agent,
        )
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=DEFAULT_NIKTO_TIMEOUT_SECONDS + 15,
            check=False,
        )
        if completed.returncode not in (0, 1) and not completed.stdout.strip():
            raise RuntimeError(
                f"Nikto exited with code {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )
        return parse_nikto_output(completed.stdout)

    def run(self, current_task: Task) -> None:
        target_url = get_target_url(current_task)
        self.log.info("Running Nikto scan on %s", target_url)

        try:
            findings = self._scan_url(target_url)
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
            self.log.warning("Nikto scan failed for %s: %s", target_url, exc)
            self.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Nikto scan error: {exc}",
                data=[],
            )
            return

        if findings:
            messages = [
                f"[{item.get('id', 'nikto')}] {item.get('msg') or item.get('url')}"
                for item in findings
            ]
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(sorted(set(messages)))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=findings,
        )


if __name__ == "__main__":
    Nikto.parallel_loop()
    