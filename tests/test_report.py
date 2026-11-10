"""Synthetic messages only; never open real caches or evidence."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("discord_cache_parser", ROOT / "discord_cache_parser.py")
parser = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = parser
spec.loader.exec_module(parser)


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ReportTests(unittest.TestCase):
    def message(self, timestamp, content="hello", kind=0):
        return parser.Message("123", "456", kind, content, timestamp, None,
                              parser.Author("789", "alice", "Alice", "avatar"), [])

    def report(self, messages, avatars=None):
        channel = parser.Channel("456", messages, {m.author for m in messages})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            parser.render_html_report(path, {"456": channel} if messages else {}, avatars or {}, {})
            return (path / "index.html").read_text(), (path / "evidence.html").read_text()

    def test_chat_and_original_evidence(self):
        msg = self.message("2026-11-10T12:00:00Z", "**Hi** <@789> <script>alert(1)</script>")
        msg.edited_timestamp = "2026-11-10T12:01:00Z"
        chat, evidence = self.report([msg])
        self.assertIn("<strong>Hi</strong>", chat)
        self.assertIn('@Alice</span>', chat)
        self.assertIn("(edited)", chat)
        self.assertIn('href="evidence.html"', chat)
        self.assertIn("Message ID: 123", chat)
        self.assertIn("&lt;script&gt;", chat)
        self.assertNotIn("script", [tag for tag, _ in Elements(chat).elements])
        self.assertIn("<table>", evidence)
        self.assertIn("**Hi**", evidence)

    def test_grouping_and_day_boundaries(self):
        chat, _ = self.report([self.message("2026-11-10T23:58:00Z"),
                               self.message("2026-11-10T23:59:00Z"),
                               self.message("2026-11-11T00:00:00Z"),
                               self.message("2026-11-11T00:08:00Z")])
        articles = [attrs for tag, attrs in Elements(chat).elements if tag == "article"]
        self.assertEqual(["grouped" in a["class"].split() for a in articles], [False, True, False, False])
        self.assertIn("11 November 2026", chat)

    def test_cached_media_and_missing_attachments(self):
        msg = self.message("2026-11-10T12:00:00Z")
        image = parser.AttachmentFile("hash", "attachments/test image.png", 123)
        avatar = parser.AttachmentFile("avatar", "avatars/avatar.png", 12)
        msg.attachments = [parser.Attachment("a", "photo.png", "https://example.invalid/private", None, "image/png", [image]),
                           parser.Attachment("b", "missing.png", "https://example.invalid/missing", None, None)]
        chat, _ = self.report([msg], {"avatar": [parser.CachedAvatar("avatar", "avatar", "avatar.png", [avatar])]})
        sources = [attrs["src"] for tag, attrs in Elements(chat).elements if tag == "img"]
        self.assertEqual(sources, ["avatars/avatar.png", "attachments/test%20image.png"])
        self.assertIn("missing.png · not cached", chat)
        self.assertNotIn("https://example.invalid", chat)

    def test_bold_can_contain_italics(self):
        self.assertEqual(
            parser.render_message_content("**bold *it* x**", {}),
            "<strong>bold <em>it</em> x</strong>",
        )

    def test_triple_asterisks_keep_bold_italics(self):
        self.assertEqual(
            parser.render_message_content("***x***", {}),
            "<strong><em>x</em></strong>",
        )

    def test_repeated_asterisks_do_not_exhaust_recursion(self):
        for content in ["*" * 3999 + "x", "**" * 2000 + "x", "**a" * 1333]:
            with self.subTest(length=len(content), ending=content[-3:]):
                rendered = parser.render_message_content(content, {})
                self.assertIsInstance(rendered, str)
                self.assertIn(content[-1], rendered)

    def test_italics_require_non_whitespace_boundaries(self):
        for content in ["2 * 3 * 4", "* a*", "*a *"]:
            with self.subTest(content=content):
                self.assertEqual(parser.render_message_content(content, {}), content)
        self.assertEqual(parser.render_message_content("*a*", {}), "<em>a</em>")

    def test_fenced_code_language_tag(self):
        self.assertEqual(
            parser.render_message_content("```py\nprint(1)```", {}),
            "<pre><code>print(1)</code></pre>",
        )
        self.assertEqual(
            parser.render_message_content("```print(1)```", {}),
            "<pre><code>print(1)</code></pre>",
        )

    def test_nested_formatting_and_fenced_code_escape_html(self):
        for content in [
            "**bold *<script>alert(1)</script>* <img src=x>**",
            "```py\n<script>alert(1)</script><img src=x>```",
        ]:
            with self.subTest(content=content):
                rendered = parser.render_message_content(content, {})
                tags = [tag for tag, _ in Elements(rendered).elements]
                self.assertNotIn("script", tags)
                self.assertNotIn("img", tags)
                self.assertIn("&lt;script&gt;", rendered)
                self.assertIn("&lt;img src=x&gt;", rendered)

    def test_code_escaping_and_path_validation(self):
        content = parser.render_message_content('`<img src=x>` ```<script>```', {})
        self.assertNotIn("<img", content)
        self.assertNotIn("<script>", content)
        for path in ["../secret", "/tmp/image.png", "https://example.com/a.png", "avatars/../../file"]:
            self.assertEqual(parser.local_file_url(parser.AttachmentFile("x", path, 1)), "")

    def test_empty_report_and_invalid_timestamp(self):
        chat, evidence = self.report([])
        self.assertIn("No messages recovered", chat)
        self.assertIn("Additional Cached Attachments", evidence)
        chat, _ = self.report([self.message("unknown", kind=3)])
        self.assertIn("CALL (3)", chat)
        self.assertIn("unknown", chat)

    def test_json_schema_unchanged(self):
        msg = self.message("2026-11-10T12:00:00Z", "**raw**")
        result = parser.message_to_dict(msg)
        self.assertEqual(result["content"], "**raw**")
        self.assertEqual(result["timestamp"], msg.timestamp)
        self.assertEqual(result["author"]["username"], "alice")


if __name__ == "__main__":
    unittest.main()
