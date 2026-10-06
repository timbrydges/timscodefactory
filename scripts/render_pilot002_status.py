"""Render a saved operator observation as a standalone, escaped, offline HTML page."""
import argparse
import html
import json
from pathlib import Path


def escape(value):
    return html.escape(str(value),quote=True)


def money(value):
    if type(value) is not int or value<0:raise ValueError('Invalid money field')
    return f'US${value//1000000}.{value%1000000:06d}'


def render(report):
    if report.get('execution_authorized') is not False or report.get('gate_authority') is not False:
        raise ValueError('Report must grant no authority')
    task=report['task']
    workers=''.join('<tr><th scope="row">'+escape(name)+'</th><td>'+(
        'Disabled observed' if row.get('disabled_observed') is True else 'Not confirmed disabled')+
        '</td><td>'+escape(row.get('status','UNKNOWN'))+'</td></tr>'
        for name,row in report['workers'].items())
    attempts=''.join('<tr><th scope="row">'+escape(name)+'</th><td>'+escape(row['status'])+
        '</td><td>'+(money(row['reserved_micro_usd']) if 'reserved_micro_usd' in row else 'Unknown / absent')+
        '</td><td>'+(money(row['reported_actual_micro_usd']) if row.get('reported_actual_micro_usd') is not None else 'Not recorded')+
        '</td></tr>' for name,row in report['attempts'].items())
    total=money(report['known_reserved_micro_usd'])
    if report.get('reservation_total_complete') is not True:total+=' (incomplete)'
    task_text=escape(task.get('state','UNKNOWN'))+' · version '+escape(task.get('version','unknown'))
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Factory operator snapshot</title><style>
body{font:16px/1.5 system-ui,sans-serif;background:#f3f5f8;color:#172435;margin:0}
main{max-width:1000px;margin:auto;padding:28px}h1{font-size:32px;margin-bottom:4px}
.notice{background:#fff1c5;border-left:5px solid #947000;padding:15px;margin:24px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
section,.card{background:white;border:1px solid #d8dfe9;border-radius:10px;padding:18px;margin:16px 0}
.card strong{display:block;font-size:23px}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px;border-bottom:1px solid #e2e7ee}th{font-weight:600}
small{color:#47566b}h2{font-size:21px}footer{margin:24px 0;color:#47566b}
</style><main><small>TIM'S SOFTWARE FACTORY · OPERATOR VIEW</small>
<h1>Factory status</h1><p>Saved observation: '''+escape(report['finished_at'])+'''</p>
<div class="notice"><strong>Snapshot only — not a live control panel.</strong>
This page cannot start workers, spend money, approve a release or advance a task.
Refresh by collecting a new report; do not use this saved page as activation evidence.</div>
<div class="cards"><div class="card">Authoritative task<strong>'''+task_text+'''</strong></div>
<div class="card">Known reservations<strong>'''+escape(total)+'''</strong><small>Held budget, not an invoice.</small></div>
<div class="card">Read completeness<strong>'''+escape(report['status'])+'''</strong></div></div>
<section><h2>Pilot workers</h2><div class="scroll"><table><thead><tr><th>Worker</th><th>Execution</th><th>Read</th></tr></thead><tbody>'''+workers+'''</tbody></table></div></section>
<section><h2>Consumed attempts and reservations</h2><p>STARTED means a consumed attempt with an unresolved or incomplete runtime record; it is not permission to retry. Offline review acceptance does not change that record.</p>
<div class="scroll"><table><thead><tr><th>Attempt</th><th>Ledger status</th><th>Reserved</th><th>Reported cost</th></tr></thead><tbody>'''+attempts+'''</tbody></table></div>
<p>Missing reported costs are unknown, not zero. Provider invoices are not verified.</p></section>
<footer>Scope: '''+escape(report['scope'])+'''<br>Unavailable reads: '''+escape(', '.join(report['unavailable']) or 'None')+'''</footer></main></html>'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('report',type=Path);p.add_argument('output',type=Path)
    args=p.parse_args()
    if args.report.stat().st_size>65536:raise ValueError('Report exceeds bound')
    page=render(json.loads(args.report.read_bytes()))
    with args.output.open('x',encoding='utf-8') as stream:stream.write(page)
    print('Offline operator page created')


if __name__=='__main__':main()
