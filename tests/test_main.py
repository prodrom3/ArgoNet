"""Integration tests for the argonet entry point."""

import unittest
from unittest.mock import patch, MagicMock

from argonet import _deduplicate, main
from core.output import Renderer


class TestMain(unittest.TestCase):
    @patch("argonet.Renderer")
    def test_single_target(self, mock_renderer_cls: MagicMock) -> None:
        mock_renderer = MagicMock(spec=Renderer)
        mock_renderer_cls.return_value = mock_renderer
        exit_code = main(["--no-traceroute", "8.8.8.8"])
        mock_renderer.analysis.assert_called_once()
        self.assertEqual(exit_code, 0)

    @patch("argonet.Renderer")
    def test_multiple_targets(self, mock_renderer_cls: MagicMock) -> None:
        mock_renderer = MagicMock(spec=Renderer)
        mock_renderer_cls.return_value = mock_renderer
        exit_code = main(["--no-traceroute", "8.8.8.8", "1.1.1.1"])
        self.assertEqual(mock_renderer.analysis.call_count, 2)
        self.assertEqual(exit_code, 0)

    @patch("core.pipeline.resolve_domain", return_value=[])
    @patch("argonet.Renderer")
    def test_dns_failure_exit_code_1(self, mock_renderer_cls: MagicMock, _: MagicMock) -> None:
        mock_renderer = MagicMock(spec=Renderer)
        mock_renderer_cls.return_value = mock_renderer
        self.assertEqual(main(["--no-traceroute", "bad.invalid"]), 1)

    @patch("argonet.Renderer")
    def test_json_output(self, mock_renderer_cls: MagicMock) -> None:
        mock_renderer = MagicMock(spec=Renderer)
        mock_renderer_cls.return_value = mock_renderer
        main(["--json", "--no-traceroute", "8.8.8.8"])
        mock_renderer.json_output.assert_called_once()

    @patch("argonet.Renderer")
    def test_dedup(self, mock_renderer_cls: MagicMock) -> None:
        mock_renderer = MagicMock(spec=Renderer)
        mock_renderer_cls.return_value = mock_renderer
        main(["--no-traceroute", "8.8.8.8", "8.8.8.8", "1.1.1.1"])
        self.assertEqual(mock_renderer.analysis.call_count, 2)

    def test_version_flag(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class TestDeduplicate(unittest.TestCase):
    def test_removes_duplicates(self) -> None:
        self.assertEqual(_deduplicate(["a", "b", "a"]), ["a", "b"])

    def test_preserves_order(self) -> None:
        self.assertEqual(_deduplicate(["c", "b", "a"]), ["c", "b", "a"])

    def test_empty(self) -> None:
        self.assertEqual(_deduplicate([]), [])


if __name__ == "__main__":
    unittest.main()
