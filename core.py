"""Encrypted single-owner storage and deterministic mail organization."""
import base64, hashlib, html, json, re, sqlite3
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from contextlib import contextmanager
from zoneinfo import ZoneInfo
from cryptography.fernet import Fernet

class Store:
    def __init__(self, path, key):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.cipher = Fernet(key.encode())
        with self.conn() as c:
            c.execute('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB NOT NULL)')
    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.execute('PRAGMA journal_mode=WAL')
        try:
            with c: yield c
        finally: c.close()
    def get(self, key, default=None):
        with self.conn() as c: row=c.execute('SELECT v FROM kv WHERE k=?',(key,)).fetchone()
        return json.loads(self.cipher.decrypt(row[0])) if row else default
    def put(self, key, value):
        self.put_many({key:value})
    def put_many(self, values):
        with self.conn() as c:
            for key,value in values.items():
                enc=self.cipher.encrypt(json.dumps(value,ensure_ascii=False).encode())
                c.execute('INSERT OR REPLACE INTO kv VALUES (?,?)',(key,enc))
    def delete(self,*keys):
        with self.conn() as c:
            c.executemany('DELETE FROM kv WHERE k=?',[(k,) for k in keys])
    def take(self,key):
        with self.conn() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT v FROM kv WHERE k=?',(key,)).fetchone()
            c.execute('DELETE FROM kv WHERE k=?',(key,))
        return json.loads(self.cipher.decrypt(row[0])) if row else None

def iso(ms): return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat()
def digest_query(start_ms,end_ms):
    # Overfetch one second, then filter exact milliseconds. Gmail after/before are exclusive.
    return f'after:{start_ms//1000-1} before:{end_ms//1000+1} -in:spam -in:trash -in:sent -in:drafts'
COMMENT_RE=re.compile(r'<!--[\s\S]*?-->|<!\[endif\]-->',re.S)
BLOCK_RE=re.compile(r'<(style|script|head|title|xml|noscript)\b[^>]*>[\s\S]*?</\1>|<(meta|link|base)\b[^>]*>',re.S|re.I)
HIDDEN_RE=re.compile(r'<(div|p|span|td)\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|max-height\s*:\s*0|font-size\s*:\s*0|mso-hide\s*:\s*all|aria-hidden\s*=\s*["\']?true)[^>]*>[\s\S]*?</\1>',re.S|re.I)
TAG_RE=re.compile(r'<[^>]+>')
URL_RE=re.compile(r'(?:https?://|www\.)[^\s<>"\'））】」]+',re.I)
TOKEN_RE=re.compile(r'\b[A-Za-z0-9+/_-]{32,}={0,2}')
CSSID_RE=re.compile(r'\b(?=[\w.+-]*[A-Z])(?=[\w.+-]*[.])[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+){2,}\b')
ZW_RE=re.compile(r'[​‌‍﻿­]')
# Literal comment residue: some senders escape conditional comments into visible text.
LITERAL_COMMENT_RE=re.compile(r'<!--\[if[^\]]*\]>\s*<!-->|<!--<!\[endif\]-->|<!\[endif\]-->|<!--[\s\S]{0,200}?-->|<!--|-->')
def clean_text(value):
    """Remove markup residue, tracking URLs and machine tokens from extracted text."""
    value=html.unescape(value)
    value=LITERAL_COMMENT_RE.sub(' ',value)
    value=re.sub(r'<\s*>','',value)
    value=re.sub(r'<([A-Za-z][A-Za-z0-9 .-]{0,40})>',r'\1',value)
    value=ZW_RE.sub('',value)
    value=URL_RE.sub(' ',value)
    value=TOKEN_RE.sub(' ',value)
    value=CSSID_RE.sub(' ',value)
    return re.sub(r'\s+',' ',value).strip()
def smart_truncate(value,limit=360):
    if len(value)<=limit:return value
    cut=value[:limit]
    tail=cut[-160:]
    at=max(tail.rfind(x) for x in ('。','！','？','. ','! ','? ','；','; '))
    if at>40:cut=cut[:len(cut)-160+at+1]
    return cut.rstrip('，,、：: ')+'…'
class PlainHTML(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.parts=[];self.skip=0
    def handle_starttag(self,tag,attrs):
        if tag in ('style','script'):self.skip+=1
    def handle_endtag(self,tag):
        if tag in ('style','script'):self.skip=max(0,self.skip-1)
    def handle_data(self,data):
        if not self.skip:self.parts.append(data)
def body_text(payload):
    plain=[];markup=[]
    def walk(part):
        if part.get('filename'):return
        body=part.get('body',{}).get('data')
        if body:
            try:text=base64.urlsafe_b64decode(body+'='*(-len(body)%4)).decode('utf-8','replace')
            except (ValueError,TypeError):text=''
            if part.get('mimeType')=='text/plain':plain.append(text)
            elif part.get('mimeType')=='text/html':markup.append(text)
        for child in part.get('parts',[]):walk(child)
    walk(payload)
    if plain:result=' '.join(plain)
    else:
        raw=' '.join(markup)
        for _ in range(3):
            cleaned=HIDDEN_RE.sub(' ',raw)
            if cleaned==raw:break
            raw=cleaned
        raw=COMMENT_RE.sub(' ',raw)
        raw=BLOCK_RE.sub(' ',raw)
        parser=PlainHTML();parser.feed(raw);result=' '.join(parser.parts)
    return clean_text(result)
CATEGORIES=('需关注','账单订阅','一般通知')
BUILTIN_RULES=[
    ('需关注',r'安全提醒|异地登录|授权|security alert|new sign.in|verify your identity|需要回复|请.{0,24}回复|截止|deadline|action required|please reply','内置关键词'),
    ('账单订阅',r'订阅|续[费期]|收据|账单|扣款|发票|subscription|renewal|receipt|invoice|payment','内置关键词'),
]
def valid_category(value):return value in CATEGORIES
def sender_domain(value):
    m=re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',value or '')
    return m.group(1).lower() if m else ''
def classify(subject,text,labels,rules=(),sender=''):
    value=(subject+' '+text).lower();domain=sender_domain(sender)
    for rule in rules:
        kind=rule.get('kind');target=(rule.get('value') or '').strip().lower()
        if not target:continue
        if kind=='domain' and domain and (domain==target or domain.endswith('.'+target)):
            return rule['category'],f'你的规则：发件域名 {target}'
        if kind=='keyword' and target in value:
            return rule['category'],f'你的规则：关键词“{rule.get("value").strip()[:24]}”'
    for category,pattern,label in BUILTIN_RULES:
        m=re.search(pattern,value)
        if m:return category,f'{label}：“{m.group(0)[:24]}”'
    return '一般通知','未命中规则，按默认归类'
def attachment_parts(payload):
    found=[]
    def walk(part,path):
        mime=part.get('mimeType','application/octet-stream').lower()
        headers={h['name'].lower():h['value'] for h in part.get('headers',[])}
        body=part.get('body',{})
        if (part.get('filename') or mime.startswith('image/') or headers.get('content-disposition','').lower().startswith('attachment')) and (body.get('attachmentId') or 'data' in body):
            found.append((path,part))
        for i,child in enumerate(part.get('parts',[])):walk(child,path+'.'+str(i))
    walk(payload,'0')
    return found

def attachment_metadata(payload,mid):
    result=[]
    for path,part in attachment_parts(payload):
        mime=part.get('mimeType','application/octet-stream').lower()[:100]
        result.append({'messageId':mid,'partId':path,'filename':part.get('filename','')[:240] or ('内嵌图片' if mime.startswith('image/') else '未命名附件'),
            'mimeType':mime,'size':max(0,int(part.get('body',{}).get('size',0))),
            'inline':not bool(part.get('filename'))})
    return result

def unsubscribe_link(headers):
    """Extract a safe one-click unsubscribe target from List-Unsubscribe headers."""
    raw=headers.get('list-unsubscribe','')[:1000]
    for candidate in re.findall(r'<([^>]+)>',raw):
        candidate=candidate.strip()
        if candidate.lower().startswith('https://') and len(candidate)<=500:return candidate[:500]
    for candidate in re.findall(r'<([^>]+)>',raw):
        candidate=candidate.strip()
        if candidate.lower().startswith('mailto:') and len(candidate)<=300:return candidate[:300]
    return None
def organize(messages,start_ms,end_ms,rules=()):
    items=[];ads=[];seen=set()
    for msg in sorted(messages,key=lambda x:int(x['internalDate']),reverse=True):
        mid=msg['id'];ts=int(msg['internalDate'])
        if mid in seen or not(start_ms<ts<=end_ms):continue
        if any(x in msg.get('labelIds',[]) for x in ('SPAM','TRASH','SENT','DRAFT')):continue
        seen.add(mid)
        headers={x['name'].lower():x['value'] for x in msg.get('payload',{}).get('headers',[])}
        title=clean_text(headers.get('subject','（无主题）'))[:300] or '（无主题）'
        sender=headers.get('from','')[:320]
        content=body_text(msg.get('payload',{})) or clean_text(msg.get('snippet',''))
        category,reason=classify(title,content,msg.get('labelIds',[]),rules,sender)
        is_code=bool(re.search(r'验证码|one.time|verification code|security code',title+' '+content,re.I))
        if is_code:title=re.sub(r'(?<!\d)\d{4,8}(?!\d)','[已隐藏]',title)
        link={'label':title,'url':f'https://mail.google.com/mail/#all/{mid}'}
        # Avoid retaining one-time passcodes in the digest.
        if is_code:excerpt='这是一封验证类通知，验证码不保存在简报中，请查看原邮件。'
        else:excerpt=smart_truncate(content)
        action={'需关注':'规则识别为需关注，请打开原邮件核对是否需要处理。','账单订阅':'金额与续期信息以原邮件和服务方账户页面为准。','一般通知':''}[category]
        item={'id':mid,'category':category,'title':title,'summary':excerpt or '邮件没有可读取的正文，请查看原邮件。','action':action,'reason':reason,'sender':sender_domain(sender),'unsubscribe':unsubscribe_link(headers),'dateLabel':datetime.fromtimestamp(ts/1000,ZoneInfo('Asia/Shanghai')).strftime('%m/%d'),'count':1,'links':[link],'attachments':attachment_metadata(msg.get('payload',{}),mid)}
        if 'CATEGORY_PROMOTIONS' in msg.get('labelIds',[]) and category=='一般通知':ads.append(item)
        else:items.append(item)
    if ads:items.append({'id':'promotions','category':'一般通知','title':f'{len(ads)} 封普通推广','summary':'按邮件标签合并推广；请按需查看原邮件。','action':'','reason':'按 Gmail 推广标签合并','sender':'','unsubscribe':None,'dateLabel':'本期','count':len(ads),'links':[x['links'][0] for x in ads],'attachments':[a for x in ads for a in x['attachments']]})
    order={'需关注':0,'账单订阅':1,'一般通知':2};items.sort(key=lambda x:order[x['category']])
    count=sum(x['count'] for x in items);important=sum(x['count'] for x in items if x['category']=='需关注')
    return {'id':str(end_ms),'generatedAt':iso(end_ms),'rangeStart':iso(start_ms),'rangeEnd':iso(end_ms),'total':count,'headline':f'本期 {count} 封邮件，{important} 封需关注。规则归类，正文摘录。' if count else '本期没有新邮件。','items':items}
