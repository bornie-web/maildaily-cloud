"""163 INBOX adapter. TLS, EXAMINE and BODY.PEEK only; never STORE/EXPUNGE.

Credentials stay in the existing encrypted Store. No arbitrary IMAP hosts.
"""
import asyncio
import base64
import imaplib
import re
import ssl
import time
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, SecretStr
from core import organize, attachment_metadata, attachment_parts
from aisummary import ai_summary_config, apply_ai_summary

MAX_MESSAGE = 20 * 1024 * 1024
MAX_BATCH = 50 * 1024 * 1024
MAX_CANDIDATES = 200
PREFIX = 'netease.'
DEFAULT_SCHEDULE = {'time': '19:00', 'enabled': False, 'timezone': 'Asia/Shanghai'}


def check(status, message):
    if status != 'OK':
        raise HTTPException(502, message)


@contextmanager
def inbox(account):
    client = None
    try:
        client = imaplib.IMAP4_SSL('imap.163.com', 993,
                                  ssl_context=ssl.create_default_context(), timeout=15)
        check(client.login(account['email'], account['code'])[0], '163 登录失败，请检查客户端授权码。')
        if b'ID' in client.capabilities:
            # ID extension is required by some NetEase accounts. Identify truthfully.
            imaplib.Commands.setdefault('ID', ('AUTH', 'SELECTED'))
            check(client._simple_command('ID', '("name" "MailDaily" "version" "0.3" "vendor" "MailDaily")')[0],
                  '163 客户端识别失败，请检查网易客户端访问设置。')
        check(client.select('INBOX', readonly=True)[0],
              '163 拒绝只读访问，请在网易网页邮箱确认 IMAP 已开启、授权码有效及客户端安全设置。')
        response = client.response('UIDVALIDITY')[1]
        if not response or not response[0] or not response[0].isdigit():
            raise HTTPException(502, '163 未返回稳定的邮箱标识，本次未保存。')
        yield client, int(response[0])
    except HTTPException:
        raise
    except imaplib.IMAP4.error:
        raise HTTPException(502, '163 连接被拒绝。请使用客户端授权码，并在网易网页端检查 IMAP 和安全提醒。') from None
    except (OSError, ValueError, UnicodeError):
        raise HTTPException(502, '无法安全连接 163，请检查云端网络后重试；未修改原邮件。') from None
    finally:
        if client:
            # Do not CLOSE: use logout without any expunge operation.
            with suppress(Exception):
                client.logout()


def message_id(validity, uid):
    if not (0 < validity <= 0xffffffff and 0 < uid <= 0xffffffff):
        raise HTTPException(502, '163 邮件标识无效。')
    return f'{validity:08x}{uid:08x}'


def mime_payload(part):
    headers = [{'name': k, 'value': str(v)} for k, v in part.items()]
    result = {'mimeType': part.get_content_type(), 'filename': part.get_filename() or '', 'headers': headers}
    if part.is_multipart():
        result['parts'] = [mime_payload(p) for p in part.iter_parts()]
    else:
        raw = part.get_payload(decode=True) or b''
        # Normalize textual parts to UTF-8 before sharing Gmail's body cleaner.
        if part.get_content_maintype() == 'text' and not part.get_filename():
            try:
                raw = raw.decode(part.get_content_charset() or 'utf-8', 'replace').encode('utf-8')
            except LookupError:
                raw = raw.decode('utf-8', 'replace').encode('utf-8')
            result['headers'] = [h for h in headers if h['name'].lower() != 'content-type']
            result['headers'].append({'name': 'Content-Type', 'value': part.get_content_type() + '; charset=utf-8'})
        result['body'] = {'size': len(raw), 'data': base64.urlsafe_b64encode(raw).decode()}
    return result


def read_message(client, validity, uid, budget):
    check_deadline(budget)
    status, rows = client.uid('FETCH', str(uid), '(UID INTERNALDATE RFC822.SIZE)')
    check(status, '163 邮件信息读取失败，本期未保存。')
    meta = b' '.join(x for x in rows if isinstance(x, bytes))
    size = re.search(rb'RFC822.SIZE (\d+)', meta)
    date = re.search(rb'INTERNALDATE "([^"]+)"', meta)
    if not size or not date:
        raise HTTPException(502, '163 邮件已移动或信息不完整，请重试。')
    n = int(size[1])
    stamp = int(parsedate_to_datetime(date[1].decode()).timestamp() * 1000)
    if 'start' in budget and not budget['start'] < stamp <= budget['end']:
        return None
    if n > MAX_MESSAGE or budget['bytes'] + n > MAX_BATCH:
        raise HTTPException(413, '本次含超大邮件（单封20MB或整期50MB上限），未推进进度；请在原邮箱查看。')
    # Limit literal size requested as an additional memory guard.
    status, rows = client.uid('FETCH', str(uid), f'(UID BODY.PEEK[]<0.{MAX_MESSAGE + 1}>)')
    check(status, '163 邮件正文读取失败，本期未保存。')
    chunks = [x[1] for x in rows if isinstance(x, tuple) and isinstance(x[1], bytes)]
    raw = b''.join(chunks)
    if len(raw) != n or len(raw) > MAX_MESSAGE:
        raise HTTPException(502, '163 邮件下载不完整，本期未保存。')
    budget['bytes'] += len(raw)
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    return {'id': message_id(validity, uid), 'internalDate': str(stamp), 'labelIds': [],
            'payload': mime_payload(parsed)}


def check_deadline(budget):
    if time.monotonic() > budget['deadline']:
        raise HTTPException(504, '163 读取超时，旧简报和进度不变，请稍后重试。')


def fetch_mail(account, start, end):
    budget = {'bytes': 0, 'deadline': time.monotonic() + 85, 'start': start, 'end': end}
    # IMAP date-only search overfetches one day either side, then INTERNALDATE filters exactly.
    months = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
    def day(ms, offset):
        d = datetime.fromtimestamp(ms / 1000, timezone.utc) + timedelta(days=offset)
        return f'{d.day:02d}-{months[d.month-1]}-{d.year}'
    with inbox(account) as (client, validity):
        status, rows = client.uid('SEARCH', None, 'SINCE', day(start, -1), 'BEFORE', day(end, 2))
        check(status, '163 邮件搜索失败，本期未保存。')
        ids = sorted({int(x) for x in (rows[0] or b'').split()})
        if len(ids) > MAX_CANDIDATES:
            raise HTTPException(422, '163 搜索候选超过200封，未保存部分结果；此初版暂不适合大批量邮箱。')
        result = []
        for uid in ids:
            mail = read_message(client, validity, uid, budget)
            if mail: result.append(mail)
        return result


def fetch_attachment(account, mid, part_id):
    if not re.fullmatch(r'[a-f0-9]{16}', mid) or not re.fullmatch(r'0(?:\.[0-9]+)*', part_id):
        raise HTTPException(422, '附件标识无效。')
    with inbox(account) as (client, validity):
        if validity != int(mid[:8], 16):
            raise HTTPException(409, '网易邮箱标识已变化，请重新整理后查看附件。')
        mail = read_message(client, validity, int(mid[8:], 16), {'bytes': 0, 'deadline': time.monotonic()+60})
        part = next((p for path, p in attachment_parts(mail['payload']) if path == part_id), None)
        if part is None: raise HTTPException(404, '附件已不存在。')
        raw = base64.urlsafe_b64decode(part['body']['data'])
        if len(raw) > 10*1024*1024: raise HTTPException(413, '附件超过10MB，请在网易邮箱打开。')
        meta = next(a for a in attachment_metadata(mail['payload'], mid) if a['partId'] == part_id)
        return {**meta, 'base64': base64.b64encode(raw).decode()}


def register_netease(app, store, auth):
    lock = asyncio.Lock()
    def get(k, default=None): return store.get(PREFIX+k, default)
    def account():
        value = get('account')
        if not value: raise HTTPException(409, '请先连接163邮箱。')
        return value
    def clear():
        store.delete(*(PREFIX+k for k in ('account','digests','watermark','error','schedule','done','attempt')))
    class Login(BaseModel):
        email: str = Field(max_length=254)
        code: SecretStr = Field(min_length=1, max_length=128)
    class Schedule(BaseModel):
        time: str = Field(pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
        enabled: bool
    @app.get('/v1/netease/state', dependencies=[Depends(auth)])
    async def state():
        value = get('account', {})
        return {'connected': bool(value), 'account': value.get('email',''), 'readOnly': True,
                'schedule': get('schedule', DEFAULT_SCHEDULE), 'lastError': get('error'), 'busy': lock.locked()}
    @app.post('/v1/netease/connect', dependencies=[Depends(auth)])
    async def connect(value: Login):
        email = value.email.strip().lower(); code = value.code.get_secret_value().strip()
        if not re.fullmatch(r'[a-z0-9_.+-]+@163\.com', email) or not code or re.search(r'[\s\x00-\x1f\x7f]', code):
            raise HTTPException(422, '请填写完整的 @163.com 邮箱和无空格的客户端授权码。')
        async with lock:
            saved = get('account')
            if saved and saved['email'] != email: raise HTTPException(409, '请先断开当前163邮箱，再换另一个账号。')
            value = {'email': email, 'code': code}
            def verify():
                with inbox(value): pass
            await asyncio.to_thread(verify)
            store.put(PREFIX+'account', value)
        return {'connected': True}
    @app.delete('/v1/netease/account', dependencies=[Depends(auth)])
    async def disconnect():
        async with lock: clear()
        return {'cleared': True, 'revocationRequired': True}
    @app.get('/v1/netease/digests', dependencies=[Depends(auth)])
    async def digests():
        return {'account': get('account',{}).get('email',''), 'scheduleLabel': '163 收件箱 · 只读', 'digests': get('digests',[])}
    async def sync(key=None):
        if lock.locked(): raise HTTPException(409, '163正在连接或整理，请稍后刷新。')
        async with lock:
            saved = account(); end = int(time.time()*1000); start = get('watermark', end-86400000)
            try:
                messages = await asyncio.to_thread(fetch_mail, saved, start, end)
                digest = organize(messages, start, end)
                try:
                    import os
                    await apply_ai_summary(digest, ai_summary_config(os.getenv))
                except Exception:
                    pass
                for item in digest['items']:
                    item['links'] = [{'label': item['title'], 'url': 'https://mail.163.com/'}]
                    item['unsubscribe'] = None
                values = {PREFIX+'digests': [digest]+get('digests',[])[:29], PREFIX+'watermark': end, PREFIX+'error': None}
                if key: values[PREFIX+'done'] = key
                store.put_many(values)
            except Exception as e:
                detail = e.detail if isinstance(e, HTTPException) else '163整理失败，旧简报与进度不变。'
                store.put(PREFIX+'error', detail)
                raise HTTPException(502, detail) from None
        return digest
    @app.post('/v1/netease/sync', dependencies=[Depends(auth)])
    async def manual_sync(): return await sync()
    @app.put('/v1/netease/schedule', dependencies=[Depends(auth)])
    async def schedule(value: Schedule):
        async with lock: store.put(PREFIX+'schedule', {**value.model_dump(), 'timezone': 'Asia/Shanghai'})
        return {'saved': True}
    @app.get('/v1/netease/messages/{mid}/attachments/{part_id}', dependencies=[Depends(auth)])
    async def attachment(mid: str, part_id: str):
        async with lock:
            saved = account()
            known = any(a['messageId']==mid and a['partId']==part_id for d in get('digests',[]) for i in d['items'] for a in i.get('attachments',[]))
            if not known: raise HTTPException(404, '附件不在当前163简报中。')
            return await asyncio.to_thread(fetch_attachment, saved, mid, part_id)
    async def tick():
        pref = get('schedule', DEFAULT_SCHEDULE)
        if not pref['enabled'] or not get('account') or lock.locked(): return
        now = datetime.now(ZoneInfo('Asia/Shanghai')); key = now.strftime('%Y-%m-%d')+'@'+pref['time']
        attempt = get('attempt', {'key':'', 'at':0})
        if now.strftime('%H:%M') < pref['time'] or get('done') == key: return
        if attempt['key'] == key and time.time()-attempt['at'] < 300: return
        store.put(PREFIX+'attempt', {'key':key, 'at':time.time()})
        await sync(key)
    return tick
