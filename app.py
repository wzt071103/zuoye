from flask import Flask, jsonify, render_template_string, request
import re
import sqlite3
from datetime import datetime
from pathlib import Path


app = Flask(__name__)
DB_PATH = str(Path(__file__).resolve().parent / "log.db")

RULES = [
    {
        "name": "SQL注入尝试",
        "pattern": r"\b(select|union|insert|delete|drop)\b|--|#|\/\*|\*\/",
        "level": "high",
    },
    {
        "name": "路径穿越",
        "pattern": r"\.\.[\/\\]",
        "level": "high",
    },
    {
        "name": "XSS 尝试",
        "pattern": r"<script\b|javascript\s*:|alert\s*\(",
        "level": "medium",
    },
    {
        "name": "大量失败登录",
        "pattern": r"(login.*fail|fail.*login)",
        "level": "medium",
    },
]


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw TEXT,
                matched_rule TEXT,
                level TEXT,
                detect_time TEXT
            )
            """
        )


def detect_line(line):
    for rule in RULES:
        if re.search(rule["pattern"], line, flags=re.IGNORECASE):
            return rule
    return None


def save_log(raw, rule):
    if not rule:
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO logs(raw, matched_rule, level, detect_time) VALUES (?, ?, ?, ?)",
            (
                raw,
                rule["name"],
                rule["level"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )


HTML_TPL = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>日志异常分析</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui; }
        body { background: #f4f7fa; padding: 20px; }
        .wrap { max-width: 1100px; margin: auto; }
        h1 { margin-bottom: 16px; color: #222; }
        .panel { background: white; border-radius: 10px; padding: 18px; margin-bottom: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        @media(max-width:720px){ .row { grid-template-columns: 1fr; } }
        #chart-wrap { height: 320px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; }
        th { background: #f0f5ff; }
        .high { color: #e63946; font-weight: bold; }
        .medium { color: #fca311; }
        textarea { width: 100%; height: 140px; padding: 10px; font-family: Consolas; }
        button { margin-top: 10px; padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="wrap">
        <h1>日志异常分析 · ECharts 可视化</h1>
        <div class="panel">
            <h3>上传 / 粘贴日志</h3>
            <form id="form">
                <textarea id="logtext" placeholder="粘贴日志内容..."></textarea>
                <br>
                <button type="submit">分析日志</button>
            </form>
        </div>
        <div class="panel">
            <h3>风险等级分布</h3>
            <div id="chart-wrap"></div>
        </div>
        <div class="panel">
            <h3>异常记录</h3>
            <table>
                <thead>
                    <tr><th>时间</th><th>规则</th><th>等级</th><th>片段</th></tr>
                </thead>
                <tbody id="table-body"></tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <script>
        const chartIns = echarts.init(document.getElementById('chart-wrap'));

        async function refresh() {
            const res = await fetch("/api/data");
            if (!res.ok) throw new Error("无法读取数据");
            const data = await res.json();
            const tbody = document.getElementById("table-body");
            tbody.replaceChildren();
            const cnt = { high: 0, medium: 0 };

            data.forEach(row => {
                cnt[row.level] = (cnt[row.level] || 0) + 1;
                const tr = document.createElement("tr");
                const values = [
                    row.detect_time,
                    row.matched_rule,
                    row.level === "high" ? "高危" : "中危",
                    row.raw.slice(0, 80)
                ];
                values.forEach((value, index) => {
                    const td = document.createElement("td");
                    td.textContent = value;
                    if (index === 2) td.className = row.level;
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });

            chartIns.setOption({
                tooltip: { trigger: "item" },
                series: [{
                    type: "pie",
                    radius: ["40%", "70%"],
                    data: [
                        { name: "高危", value: cnt.high, itemStyle: { color: "#e63946" } },
                        { name: "中危", value: cnt.medium, itemStyle: { color: "#fca311" } }
                    ]
                }]
            });
        }

        document.getElementById("form").onsubmit = async function (e) {
            e.preventDefault();
            const txt = document.getElementById("logtext").value;
            const res = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ log: txt })
            });
            if (!res.ok) {
                const err = await res.json();
                alert(err.msg || "分析失败");
                return;
            }
            await refresh();
        };

        refresh();
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TPL)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "log" not in body:
        return jsonify({"ok": False, "msg": "缺少 log 字段"}), 400
    if not isinstance(body["log"], str):
        return jsonify({"ok": False, "msg": "log 必须是字符串"}), 400

    hit = 0
    for line in body["log"].splitlines():
        rule = detect_line(line)
        if rule:
            save_log(line, rule)
            hit += 1
    return jsonify({"ok": True, "hit": hit})


@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT detect_time, matched_rule, level, raw
            FROM logs
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()
    return jsonify(
        [
            {
                "detect_time": row[0],
                "matched_rule": row[1],
                "level": row[2],
                "raw": row[3],
            }
            for row in rows
        ]
    )


init_db()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
