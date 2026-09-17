from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Generate a compact PDF artifact without requiring a GUI runtime."""

    def generate(self, path: str | Path, title: str, summary: dict[str, Any], records: list[dict[str, Any]]) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        lines = [title, "", "Executive summary", json.dumps(summary, default=str), "", "Top indicators"]
        lines.extend(f"{item.get('ioc_value', '')} | score={item.get('severity_score', 0)}" for item in records[:20])
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen.canvas import Canvas
            canvas = Canvas(str(target), pagesize=letter)
            _, height = letter
            y = height - 48
            for line in lines:
                for chunk in (line[i:i + 100] for i in range(0, len(line), 100)) or [""]:
                    canvas.drawString(36, y, chunk)
                    y -= 14
                    if y < 40:
                        canvas.showPage()
                        y = height - 48
            canvas.save()
        except ImportError:
            # Minimal valid PDF fallback for offline installations.
            text = "\\n".join(lines).replace("(", "\\(").replace(")", "\\)")
            stream = f"BT /F1 10 Tf 36 760 Td ({text[:3000]}) Tj ET".encode()
            objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"]
            output = bytearray(b"%PDF-1.4\n")
            offsets = []
            for index, obj in enumerate(objects, 1):
                offsets.append(len(output))
                output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
            start = len(output)
            output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
            output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets))
            output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF".encode())
            target.write_bytes(output)
        return target
