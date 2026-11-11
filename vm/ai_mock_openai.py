#!/usr/bin/env python3
"""Deterministic OpenAI-API test double (Responses and Chat Completions) for
isolated XP25 guest runs. It listens on loopback inside the private network
namespace, behind the XP25 gateway, and records every request's shape (never
used with real credentials or real model output).

Behavior: a user turn mentioning Event Viewer gets a function_call to
eventlog_read; a function_call_output gets a final message that quotes the
first record's source (proving tool data round-tripped); anything else gets
a fixed greeting."""
import argparse
import json
from pathlib import Path
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARK = 'MOCK-OPENAI-RESPONSES'


def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return ' '.join(part.get('text', '') for part in content if isinstance(part, dict))
    return ''


def decide(items):
    last = items[-1] if items else {}
    if last.get('type') == 'function_call_output' or last.get('role') == 'tool':
        output = last.get('output', last.get('content', ''))
        if 'withheld' in output:
            return ('text', MARK + ': the tool ran on your computer, but its output was withheld from me.')
        try:
            records = json.loads(output).get('records', [])
        except (ValueError, AttributeError):
            records = []
        source = records[0].get('source', 'unknown') if records else 'none'
        return ('text', '%s: I reviewed %d Event Viewer record(s); the latest comes from %s.' % (MARK, len(records), source))
    question = text_of(last.get('content', '')).lower()
    if 'event viewer' in question:
        return ('call', 'eventlog_read', json.dumps({'log': 'System', 'types': ['error', 'warning'], 'max_records': 5}))
    if 'connection test' in question:
        return ('text', 'READY')
    return ('text', MARK + ': hello from the isolated test provider.')


def make_handler(key, log):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0') or 0))
            record = {'time': time.time(), 'path': self.path, 'bytes': len(body),
                      'authorized': self.headers.get('Authorization') == 'Bearer ' + key}
            try:
                request = json.loads(body)
            except ValueError:
                request = {}
            items = request.get('input') or request.get('messages') or []
            record.update(model=request.get('model'), store=request.get('store'), tools=len(request.get('tools', [])),
                          items=[i.get('type') or i.get('role') for i in items if isinstance(i, dict)],
                          withheld_placeholder='withheld' in body.decode(errors='replace'))
            with open(log, 'a') as f:
                f.write(json.dumps(record) + '\n')
            if not record['authorized']:
                return self.send_json(401, {'error': {'message': 'Incorrect API key provided.', 'type': 'invalid_request_error',
                                                      'code': 'invalid_api_key'}})
            decision = decide([i for i in items if isinstance(i, dict)])
            if self.path == '/v1/responses':
                if decision[0] == 'call':
                    output = [{'type': 'function_call', 'id': 'fc_mock', 'call_id': 'call_mock_1', 'name': decision[1],
                               'arguments': decision[2], 'status': 'completed'}]
                else:
                    output = [{'type': 'message', 'id': 'msg_mock', 'role': 'assistant', 'status': 'completed',
                               'content': [{'type': 'output_text', 'text': decision[1], 'annotations': []}]}]
                return self.send_json(200, {'id': 'resp_mock', 'object': 'response', 'status': 'completed',
                                            'model': request.get('model'), 'output': output, 'error': None})
            if self.path == '/v1/chat/completions':
                message = {'role': 'assistant', 'content': None}
                if decision[0] == 'call':
                    message['tool_calls'] = [{'id': 'call_mock_1', 'type': 'function',
                                              'function': {'name': decision[1], 'arguments': decision[2]}}]
                else:
                    message['content'] = decision[1]
                return self.send_json(200, {'id': 'chatcmpl_mock', 'object': 'chat.completion',
                                            'choices': [{'index': 0, 'message': message, 'finish_reason': 'stop'}]})
            self.send_json(404, {'error': {'message': 'Unknown path.', 'code': 'not_found'}})

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', default='127.0.0.1:9000')
    parser.add_argument('--key', required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    host, port = args.listen.rsplit(':', 1)
    ThreadingHTTPServer((host, int(port)), make_handler(args.key, args.log)).serve_forever()


if __name__ == '__main__':
    main()
