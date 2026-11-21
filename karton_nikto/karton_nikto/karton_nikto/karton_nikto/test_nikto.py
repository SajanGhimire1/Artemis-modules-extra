import subprocess
import unittest
from unittest.mock import MagicMock, patch

from artemis.binds import Service, TaskStatus, TaskType
from karton.core import Task

from artemis.modules.karton_nikto import (
    Nikto,
    build_nikto_command,
    parse_nikto_output,
)


class NiktoUnitTestCase(unittest.TestCase):
    def test_build_nikto_command(self) -> None:
        cmd = build_nikto_command("https://example.com", timeout_seconds=120, tuning="12", user_agent="ArtemisBot")
        self.assertEqual(
            cmd,
            [
                "nikto",
                "-h",
                "https://example.com",
                "-Format",
                "json",
                "-maxtime",
                "120s",
                "-Tuning",
                "12",
                "-useragent",
                "ArtemisBot",
            ],
        )

    def test_parse_nikto_output_skips_invalid_lines(self) -> None:
        raw = "\n".join(
            [
                "- Nikto v2.5.0",
                "not json",
                '{"host":"example.com","vulnerabilities":[{"id":"999901","msg":"Test finding"}]}',
                "{bad json",
            ]
        )
        parsed = parse_nikto_output(raw)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], "999901")

    @patch("artemis.modules.karton_nikto.subprocess.run")
    def test_nikto_run_saves_interesting_on_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"vulnerabilities":[{"id":"000010","msg":"Exposed directory"}]}',
            stderr="",
        )
        module = Nikto.__new__(Nikto)
        module.log = MagicMock()
        module.save_task_result = MagicMock()

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"url": "http://example.com"},
        )
        module.run(task)

        module.save_task_result.assert_called_once()
        kwargs = module.save_task_result.call_args.kwargs
        self.assertEqual(kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(len(kwargs["data"]), 1)

    @patch("artemis.modules.karton_nikto.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nikto"], timeout=5))
    def test_nikto_run_handles_timeout(self, _mock_run: MagicMock) -> None:
        module = Nikto.__new__(Nikto)
        module.log = MagicMock()
        module.save_task_result = MagicMock()

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"url": "http://example.com"},
        )
        module.run(task)

        module.save_task_result.assert_called_once()
        kwargs = module.save_task_result.call_args.kwargs
        self.assertEqual(kwargs["status"], TaskStatus.ERROR)


if __name__ == "__main__":
    unittest.main()