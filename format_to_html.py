import json

def format_to_html(json_file, output_file):
    import html
    with open(json_file, "r") as f:
        data = json.load(f)
    html_content = """
    <!DOCTYPE html>
    <html lang="id">
    <head>
    <meta charset="UTF-8">
    <title>Laporan Hasil Scanning Tools</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f7fa; margin: 0; padding: 0; }
        .container { max-width: 1000px; margin: 40px auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 20px #0002; padding: 36px 32px; }
        h1 { color: #1976d2; text-align: center; margin-bottom: 18px; }
        .summary-box { background: #e3f2fd; border: 1.5px solid #90caf9; border-radius: 10px; margin-bottom: 25px; padding: 18px 25px; color: #1976d2; font-size: 1.1em; }
        .status-info { margin-bottom:10px;padding:10px;border-radius:7px;background:#f9fbe7;font-size:0.98em; }
        .tool-section { border: 2px solid #e3f2fd; border-radius: 10px; margin-bottom: 27px; background: #fbfcfe; box-shadow: 0 2px 8px #0001; }
        .tool-title { background: #e3f2fd; padding: 13px 22px; border-radius: 10px 10px 0 0; font-size: 1.13em; color: #1976d2; font-weight: bold; border-bottom: 1px solid #bbdefb; letter-spacing: 0.5px; }
        .tool-meta { background: #f1f8e9; padding: 8px 20px; border-bottom: 1px solid #c8e6c9; color: #558b2f; font-size: 0.97em; }
        .tool-content { padding: 18px 22px; font-size: 1.04em; color: #222; }
        .command { font-family: 'Fira Mono', 'Consolas', monospace; background: #ececec; color: #333; padding: 2px 8px; border-radius: 3px;}
        pre { background: #f1f3f4; color: #333; border-radius: 4px; padding: 12px 15px; white-space: pre-wrap; word-break: break-word; font-size: 0.97em; margin-top: 0; margin-bottom: 0; }
        .status-success { color: #388e3c; font-weight: bold;}
        .status-error { color: #d32f2f; font-weight: bold;}
        .status-timeout { color: #fbc02d; font-weight: bold;}
        .footer { color: #888; text-align: center; margin-top: 40px; font-size: 0.98em; }
        .pdf-btn { background: #1976d2; color: #fff; border: none; border-radius: 6px; padding: 8px 20px; font-size:1em; cursor: pointer; float:right;}
        .pdf-btn:hover { background: #1565c0; }
        @media print { body { background: #fff; } .container { box-shadow: none; border: 1px solid #aaa; } .pdf-btn { display: none; } }
    </style>
    </head>
    <body>
    <div class="container">
    <button class="pdf-btn" onclick="window.print()">Ekspor ke PDF</button>
    <h1>Laporan Hasil Scanning Tools</h1>
    <div class="status-info">
        <b>Keterangan Status:</b>
        <span class="status-success">&#x2714; Sukses</span>,
        <span class="status-error">&#9888; Error</span>,
        <span class="status-timeout">&#9203; Timeout</span>.
        Semua hasil dicatat, baik sukses maupun gagal, agar mudah troubleshooting dan audit.
    </div>
    """
    for entry in data:
        if entry["tool_name"] == "SUMMARY":
            html_content += f"""
            <div class="summary-box">
            <b>Total waktu eksekusi:</b> {entry['result']}<br>
            <b>Mulai:</b> {entry['start_time']}<br>
            <b>Selesai:</b> {entry['end_time']}
            </div>
            """
    for entry in data:
        if entry["tool_name"] == "SUMMARY":
            continue
        status_icon = {
            "success": "<span class='status-success'>&#x2714; Sukses</span>",
            "error": "<span class='status-error'>&#9888; Error</span>",
            "timeout": "<span class='status-timeout'>&#9203; Timeout</span>",
        }.get(entry.get("status", ""), entry.get("status", ""))
        error_box = ""
        if entry.get("status", "") != "success":
            error_box = f"<div class='status-{entry['status']}' style='padding:8px 17px;background:#fff3e0;border-radius:7px;margin:8px 0 13px 0;'><b>Catatan:</b> {html.escape(entry['error_message'])}</div>"
        html_content += f"""
        <div class="tool-section">
            <div class="tool-title">{html.escape(entry['tool_name'])} {status_icon}</div>
            <div class="tool-meta">
                <b>Command:</b> <span class="command">{html.escape(entry['command'])}</span><br>
                <b>Fungsi:</b> {html.escape(entry['description'])}<br>
                <b>Waktu eksekusi:</b> {entry['start_time']} - {entry['end_time']} ({entry['duration']} detik)
            </div>
            {error_box}
            <div class="tool-content">
                <pre>{html.escape(entry['result'])}</pre>
            </div>
        </div>
        """
    html_content += """
        <div class="footer">
            <b>Gratis & Open-Source</b> | Didedikasikan untuk komunitas pentester dan bug hunter Indonesia.<br>
            Buat pelaporan profesional tanpa biaya, terbuka untuk dikembangkan siapa saja.
        </div>
    </div>
    </body>
    </html>
    """
    with open(output_file, "w") as f:
        f.write(html_content)
    print(f"[INFO] HTML report saved to {output_file}")
