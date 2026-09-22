"""
Export Manager Service.
Formats and streams dynamic HTTP responses for JSON, CSV, and Markdown exports.
"""

from typing import Iterable, Any, Dict, List
import json
import csv
from io import StringIO
from django.http import HttpResponse

class ExportManager:
    """Creates downloadable HTTP responses for filtered datasets."""

    @classmethod
    def to_json_response(cls, data: Any, filename: str = "export.json") -> HttpResponse:
        content = json.dumps(data, indent=2, default=str)
        resp = HttpResponse(content, content_type="application/json")
        resp["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp

    @classmethod
    def to_csv_response(cls, headers: List[str], rows: Iterable[List[Any]], filename: str = "export.csv") -> HttpResponse:
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([str(c) if c is not None else "" for c in row])

        resp = HttpResponse(buffer.getvalue(), content_type="text/csv")
        resp["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp

    @classmethod
    def to_markdown_response(cls, title: str, headers: List[str], rows: Iterable[List[Any]], filename: str = "export.md") -> HttpResponse:
        lines = [
            f"# {title}",
            "",
            "| " + " | ".join(headers) + " |",
            "|" + "|".join(["---" for _ in headers]) + "|"
        ]
        for row in rows:
            clean_row = [str(c).replace("|", "\\|") if c is not None else "-" for c in row]
            lines.append("| " + " | ".join(clean_row) + " |")

        resp = HttpResponse("\n".join(lines), content_type="text/markdown")
        resp["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp
