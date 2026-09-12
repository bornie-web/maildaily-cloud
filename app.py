import asyncio, base64, hashlib, hmac, json, logging, os, re, secrets, time
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo
import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from pydantic import BaseModel, Field
from core import Store, digest_query, organize, attachment_parts, attachment_metadata, CATEGORIES, valid_category
from translation import translate_digest
from netease import register_netease
load_dotenv()
log=logging.getLogger('maildaily')
SCOPES='https://www.googleapis.com/auth/gmail.modify'
ACTION_LABELS={'archive':({'remove':['INBOX']}),'read':({'remove':['UNREAD']}),'unread':({'add':['UNREAD']}),'star':({'add':['STARRED']}),'unstar':({'remove':['STARRED']})}
class Settings:
    def __init__(self):
        self.api_key=os.getenv('APP_API_KEY','');self.key=os.getenv('DATA_ENCRYPTION_KEY','')
        self.base=os.getenv('PUBLIC_BASE_URL','').rstrip('/')
        self.client=os.getenv('GOOGLE_CLIENT_ID','');self.secret=os.getenv('GOOGLE_CLIENT_SECRET','')
        self.owner=os.getenv('OWNER_EMAIL','').strip().lower()
        self.db=os.getenv('DATABASE_PATH','./data/maildaily.sqlite3')
        self.push_access=os.getenv('EXPO_ACCESS_TOKEN','')
        if len(self.api_key)<32:raise RuntimeError('请配置至少32字符的 APP_API_KEY。')
        if not self.base.startswith('https://'):raise RuntimeError('PUBLIC_BASE_URL 必须是你云端的 HTTPS 地址。')
        if not self.client or not self.secret or not self.owner:raise RuntimeError('请配置 Google OAuth 和 OWNER_EMAIL。')
        self.redirect=self.base+'/oauth/google/callback'

def create_app(settings=None, start_scheduler=True):
    cfg=settings or Settings();store=Store(cfg.db,cfg.key);lock=asyncio.Lock()
    async def auth(authorization: str=Header(default='')):
        expected='Bearer '+cfg.api_key
        if not hmac.compare_digest(authorization.encode(),expected.encode()):raise HTTPException(401,'云端连接密钥无效。')
    async def token():
        saved=store.get('google')
        if not saved:raise HTTPException(409,'请先连接 Gmail。')
        async with httpx.AsyncClient(timeout=30) as client:
            r=await client.post('https://oauth2.googleapis.com/token',data={'client_id':cfg.client,'client_secret':cfg.secret,'refresh_token':saved['refresh_token'],'grant_type':'refresh_token'})
        if r.status_code!=200:raise HTTPException(502,'Google 授权已失效或暂不可用，请重新连接 Gmail。')
        return r.json()['access_token']
    async def fetch_mail(start,end):
        access=await token();messages=[];ids=set();cursor=None
        async with httpx.AsyncClient(timeout=45,headers={'Authorization':'Bearer '+access}) as client:
            while True:
                params={'q':digest_query(start,end),'maxResults':100}
                if cursor:params['pageToken']=cursor
                r=await client.get('https://gmail.googleapis.com/gmail/v1/users/me/messages',params=params)
                if r.status_code!=200:raise HTTPException(502,'读取 Gmail 失败，未推进整理时间。')
                page=r.json()
                for m in page.get('messages',[]):ids.add(m['id'])
                if len(ids)>1000:raise HTTPException(422,'本期超过1000封邮件，未保存部分结果。请缩小首次整理范围或提高服务端上限。')
                cursor=page.get('nextPageToken')
                if not cursor:break
            semaphore=asyncio.Semaphore(6)
            async def read(mid):
                async with semaphore:
                    r=await client.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}',params={'format':'full'})
                    if r.status_code!=200:raise HTTPException(502,'部分邮件读取失败，本期未保存，请重试。')
                    return r.json()
            messages=await asyncio.gather(*(read(mid) for mid in ids))
        return messages
    async def send_pending():
        pending=store.get('push_pending');push=store.get('push')
        if not pending or not push or pending.get('attempts',0)>=5:return
        headers={'Authorization':'Bearer '+cfg.push_access} if cfg.push_access else {}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                if pending.get('ticket'):
                    r=await client.post('https://exp.host/--/api/v2/push/getReceipts',headers=headers,json={'ids':[pending['ticket']]})
                    r.raise_for_status();receipt=r.json().get('data',{}).get(pending['ticket'])
                    if not receipt:return
                    if receipt.get('status')=='ok':store.put('push_status','delivered_to_push_service');store.delete('push_pending');return
                    if receipt.get('details',{}).get('error')=='DeviceNotRegistered':store.delete('push');store.put('push_status','device_unregistered');store.delete('push_pending');return
                    pending.pop('ticket',None);raise RuntimeError('push receipt failed')
                r=await client.post('https://exp.host/--/api/v2/push/send',headers=headers,json={'to':push,'title':'邮件简报已更新','body':'新的邮件整理结果已保存，打开应用查看。','sound':'default','data':{'digestId':pending['id']}})
                r.raise_for_status();ticket=r.json().get('data',{})
                if ticket.get('status')!='ok':raise RuntimeError('push ticket failed')
                pending['ticket']=ticket['id'];store.put('push_pending',pending);store.put('push_status','accepted')
        except Exception:
            pending['attempts']=pending.get('attempts',0)+1;store.put('push_pending',pending);store.put('push_status','failed' if pending['attempts']>=5 else 'retrying')
    async def sync(schedule_key=None):
        if lock.locked():raise HTTPException(409,'正在整理，请稍后刷新。')
        async with lock:
            end=int(time.time()*1000);start=store.get('watermark',end-24*3600*1000)
            try:
                messages=await fetch_mail(start,end);digest=organize(messages,start,end,store.get('rules',[]))
                editions=store.get('digests',[])
                values={'digests':[digest]+editions[:29],'watermark':end,'last_error':None}
                if schedule_key:values['schedule_done']=schedule_key
                if store.get('push'):values.update({'push_pending':{'id':digest['id'],'attempts':0},'push_status':'pending'})
                store.put_many(values)
            except Exception as e:
                message=e.detail if isinstance(e,HTTPException) else '云端整理失败，旧简报和统计时间保持不变。'
                store.put('last_error',message)
                if isinstance(e,HTTPException):raise
                raise HTTPException(502,message) from None
        await send_pending();return digest
    async def loop():
        while True:
            try:
                pref=store.get('schedule',{'time':'19:00','timezone':'Asia/Shanghai','enabled':True})
                now=datetime.now(ZoneInfo(pref['timezone']));key=now.strftime('%Y-%m-%d')+'@'+pref['time']+'@'+pref['timezone']
                attempt=store.get('schedule_attempt',{'key':'','at':0})
                due=now.strftime('%H:%M')>=pref['time'] and store.get('schedule_done')!=key
                if pref['enabled'] and store.get('google') and due and (attempt['key']!=key or time.time()-attempt['at']>300):
                    store.put('schedule_attempt',{'key':key,'at':time.time()})
                    await sync(key)
                await send_pending()
            except Exception:log.warning('Scheduled work could not complete; see authenticated state endpoint.')
            try:
                await netease_tick()
            except Exception:log.warning('163 scheduled work could not complete; see authenticated state endpoint.')
            await asyncio.sleep(30)
    @asynccontextmanager
    async def lifespan(app):
        task=asyncio.create_task(loop()) if start_scheduler else None
        yield
        if task:
            task.cancel()
            with suppress(asyncio.CancelledError):await task
    app=FastAPI(title='MailDaily independent cloud',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    app.state.store=store
    netease_tick=register_netease(app,store,auth)
    app.state.netease_tick=netease_tick
    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        if request.url.path.startswith('/v1/netease/'):
            return JSONResponse(status_code=422,content={'detail':'163请求格式不正确，请核对输入。'})
        return await request_validation_exception_handler(request,exc)
    @app.middleware('http')
    async def security(request,call_next):
        response=await call_next(request)
        response.headers['Cache-Control']='no-store'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Content-Type-Options']='nosniff'
        return response
    @app.get('/health')
    async def health():return {'service':'maildaily-independent','ok':True}
    @app.get('/v1/state',dependencies=[Depends(auth)])
    async def state():
        g=store.get('google',{})
        return {'connected':bool(g),'account':g.get('email'),'schedule':store.get('schedule',{'time':'19:00','timezone':'Asia/Shanghai','enabled':True}),'lastError':store.get('last_error'),'pushRegistered':bool(store.get('push')),'pushStatus':store.get('push_status','not_configured'),'translationAvailable':bool(os.getenv('GOOGLE_TRANSLATE_API_KEY','').strip()),'summaryMode':'规则归类与正文摘录','rules':store.get('rules',[]),'scope':SCOPES,'retention':'最多保存最近30期简报；可随时在 App 中清空云端历史或断开并删除全部数据。'}
    @app.get('/v1/digests',dependencies=[Depends(auth)])
    async def digests():
        pref=store.get('schedule',{'time':'19:00','timezone':'Asia/Shanghai','enabled':True})
        return {'account':store.get('google',{}).get('email',''),'scheduleLabel':'每天 '+pref['time'],'digests':store.get('digests',[])}
    class TranslationRequest(BaseModel):
        digestId:str=Field(max_length=200)
        target:str=Field(max_length=10)
    @app.post('/v1/translate',dependencies=[Depends(auth)])
    async def translate(value:TranslationRequest):
        async with lock:
            digest=next((d for d in store.get('digests',[]) if d['id']==value.digestId),None)
            if digest is None:raise HTTPException(404,'简报已不存在，请刷新。')
            try:
                return await asyncio.wait_for(translate_digest(store,digest,value.target,os.getenv('GOOGLE_TRANSLATE_API_KEY','').strip()),timeout=90)
            except TimeoutError:
                raise HTTPException(504,'翻译超时，原文已保留，请稍后重试。') from None
    async def read_attachment_message(mid):
        if not re.fullmatch(r'[a-fA-F0-9]{1,100}',mid):raise HTTPException(422,'邮件标识不正确。')
        known=any(link.get('url','').endswith('#all/'+mid) for d in store.get('digests',[]) for item in d['items'] for link in item['links'])
        if not known:raise HTTPException(404,'该邮件不在现有简报中，请刷新或打开原邮件。')
        access=await token()
        async with httpx.AsyncClient(timeout=45,headers={'Authorization':'Bearer '+access}) as client:
            r=await client.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}',params={'format':'full'})
        if r.status_code==404:raise HTTPException(404,'原邮件已删除或不可访问。')
        if r.status_code!=200:raise HTTPException(502,'读取附件信息失败，请稍后重试。')
        return r.json(),access
    @app.get('/v1/messages/{mid}/attachments',dependencies=[Depends(auth)])
    async def list_attachments(mid:str):
        message,_=await read_attachment_message(mid)
        return attachment_metadata(message.get('payload',{}),mid)
    @app.get('/v1/messages/{mid}/attachments/{part_id}',dependencies=[Depends(auth)])
    async def download_attachment(mid:str,part_id:str):
        if not re.fullmatch(r'0(?:\.[0-9]+)*',part_id) or len(part_id)>200:raise HTTPException(422,'附件标识不正确。')
        message,access=await read_attachment_message(mid)
        part=next((part for path,part in attachment_parts(message.get('payload',{})) if path==part_id),None)
        if part is None:raise HTTPException(404,'附件不存在。')
        body=part.get('body',{});limit=10*1024*1024
        if int(body.get('size',0))>limit:raise HTTPException(413,'附件超过10MB，请通过原邮件打开。')
        encoded=body.get('data','')
        if body.get('attachmentId'):
            aid=body['attachmentId']
            if not re.fullmatch(r'[A-Za-z0-9_-]+',aid):raise HTTPException(502,'附件标识无效。')
            async with httpx.AsyncClient(timeout=45,headers={'Authorization':'Bearer '+access}) as client:
                async with client.stream('GET',f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}/attachments/{aid}') as response:
                    if response.status_code!=200:raise HTTPException(502,'附件下载失败，请稍后重试。')
                    chunks=[];size=0
                    async for chunk in response.aiter_bytes():
                        size+=len(chunk)
                        if size>limit*4//3+10000:raise HTTPException(413,'附件超过10MB，请通过原邮件打开。')
                        chunks.append(chunk)
                    try:encoded=json.loads(b''.join(chunks))['data']
                    except (ValueError,KeyError):raise HTTPException(502,'附件数据无效。') from None
        if len(encoded)>limit*4//3+4:raise HTTPException(413,'附件超过10MB，请通过原邮件打开。')
        try:raw=base64.b64decode(encoded+'='*(-len(encoded)%4),altchars=b'-_',validate=True)
        except ValueError:raise HTTPException(502,'附件编码无效。') from None
        if len(raw)>limit:raise HTTPException(413,'附件超过10MB，请通过原邮件打开。')
        meta=next(a for a in attachment_metadata(message['payload'],mid) if a['partId']==part_id)
        return {**meta,'size':len(raw),'base64':base64.b64encode(raw).decode()}
    class Rule(BaseModel):
        kind:str=Field(pattern=r'^(domain|keyword)$')
        value:str=Field(min_length=1,max_length=120)
        category:str
    @app.get('/v1/rules',dependencies=[Depends(auth)])
    async def list_rules():return {'rules':store.get('rules',[])}
    @app.post('/v1/rules',dependencies=[Depends(auth)])
    async def add_rule(value:Rule):
        if not valid_category(value.category):raise HTTPException(422,'分类不正确。')
        rule=value.model_dump();rule['value']=rule['value'].strip()
        if rule['kind']=='domain':
            if not re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}',rule['value'].lower()):raise HTTPException(422,'域名格式不正确。')
            rule['value']=rule['value'].lower()
        rules=store.get('rules',[])
        if len(rules)>=100:raise HTTPException(422,'规则最多100条，请先删除不再需要的规则。')
        if any(r['kind']==rule['kind'] and r['value'].lower()==rule['value'].lower() for r in rules):
            raise HTTPException(409,'已存在相同规则。')
        rules.append(rule);store.put('rules',rules);return {'rules':rules}
    @app.delete('/v1/rules/{index}',dependencies=[Depends(auth)])
    async def delete_rule(index:int):
        rules=store.get('rules',[])
        if not 0<=index<len(rules):raise HTTPException(404,'规则不存在。')
        rules.pop(index);store.put('rules',rules);return {'rules':rules}
    class Correction(BaseModel):
        digestId:str
        itemId:str
        category:str
    @app.put('/v1/classification',dependencies=[Depends(auth)])
    async def correct_item(value:Correction):
        if not valid_category(value.category):raise HTTPException(422,'分类不正确。')
        async with lock:
            digests=store.get('digests',[])
            for digest in digests:
                if digest['id']!=value.digestId:continue
                for item in digest['items']:
                    if item['id']!=value.itemId:continue
                    item['category']=value.category
                    item['action']='分类已由你调整，请结合原邮件决定是否处理。'
                    item['reason']='你已手动纠正本条分类；不会影响未来邮件。'
                    digest['headline']='本期分类已更新，请查看下方邮件。'
                    store.put('digests',digests);store.delete('translations')
                    return {'updated':True}
            raise HTTPException(404,'邮件已不在简报中，请刷新。')
    class MailAction(BaseModel):
        ids:list[str]=Field(min_length=1,max_length=200)
        action:str=Field(pattern=r'^(archive|read|unread|star|unstar)$')
    @app.post('/v1/actions',dependencies=[Depends(auth)])
    async def apply_action(value:MailAction):
        for mid in value.ids:
            if not re.fullmatch(r'[a-fA-F0-9]{1,100}',mid):raise HTTPException(422,'邮件标识不正确。')
        known={mid for d in store.get('digests',[]) for item in d['items'] for link in item['links'] for mid in [link.get('url','').rsplit('#all/',1)[-1]]}
        unknown=[m for m in value.ids if m not in known]
        if unknown:raise HTTPException(404,'部分邮件不在现有简报中，请刷新后重试。')
        access=await token();ops=ACTION_LABELS[value.action]
        body={'ids':list(dict.fromkeys(value.ids)),'addLabelIds':ops.get('add',[]),'removeLabelIds':ops.get('remove',[])}
        async with httpx.AsyncClient(timeout=45,headers={'Authorization':'Bearer '+access}) as client:
            r=await client.post('https://gmail.googleapis.com/gmail/v1/users/me/messages/batchModify',json=body)
        if r.status_code==403:raise HTTPException(502,'Gmail 授权范围不足，请断开并重新连接 Gmail（需要修改权限才能执行归档等操作）。')
        if r.status_code not in (200,204):raise HTTPException(502,'无法确认 Gmail 操作结果，请到原邮箱核对后重试。')
        return {'applied':value.action,'count':len(set(value.ids))}
    @app.delete('/v1/digests',dependencies=[Depends(auth)])
    async def clear_digests():
        store.delete('digests','translations','watermark','schedule_done','last_error')
        return {'cleared':True}
    @app.post('/v1/sync',dependencies=[Depends(auth)])
    async def manual_sync():return await sync()
    @app.post('/v1/oauth/google/start',dependencies=[Depends(auth)])
    async def oauth_start():
        raw=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
        store.put('oauth',{'hash':hashlib.sha256(raw.encode()).hexdigest(),'expires':time.time()+600,'verifier':verifier})
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        params={'client_id':cfg.client,'redirect_uri':cfg.redirect,'response_type':'code','scope':SCOPES,'access_type':'offline','prompt':'consent','state':raw,'code_challenge':challenge,'code_challenge_method':'S256','login_hint':cfg.owner}
        return {'url':'https://accounts.google.com/o/oauth2/v2/auth?'+urlencode(params)}
    @app.get('/oauth/google/callback',response_class=HTMLResponse)
    async def callback(state:str='',code:str='',error:str=''):
        saved=store.get('oauth')
        if not saved or not hmac.compare_digest(saved['hash'],hashlib.sha256(state.encode()).hexdigest()) or saved['expires']<time.time():raise HTTPException(400,'授权会话无效或过期，请从 App 重新连接。')
        # Consume exactly once. Invalid states must not destroy a valid flow.
        saved=store.take('oauth')
        if not saved:raise HTTPException(400,'授权会话已使用。')
        if error or not code:raise HTTPException(400,'授权未完成，请回到 App 重试。')
        async with lock:
            async with httpx.AsyncClient(timeout=30) as client:
                r=await client.post('https://oauth2.googleapis.com/token',data={'client_id':cfg.client,'client_secret':cfg.secret,'code':code,'grant_type':'authorization_code','redirect_uri':cfg.redirect,'code_verifier':saved['verifier']})
                if r.status_code!=200:raise HTTPException(502,'Google 授权交换失败，请重试。')
                t=r.json()
                profile=await client.get('https://gmail.googleapis.com/gmail/v1/users/me/profile',headers={'Authorization':'Bearer '+t['access_token']})
                if profile.status_code!=200:raise HTTPException(502,'无法核对邮箱身份。')
                email=profile.json()['emailAddress'].lower()
                if email!=cfg.owner:raise HTTPException(403,'请选择此私人云端配置的邮箱账号。')
                if not t.get('refresh_token'):raise HTTPException(409,'未获得后台授权，请重新同意 Gmail 读取权限。')
                store.put('google',{'email':email,'refresh_token':t['refresh_token']})
        return '<!doctype html><html lang="zh-CN"><meta name="viewport" content="width=device-width,initial-scale=1"><title>已连接</title><body style="font:18px system-ui;padding:40px;line-height:1.8"><h1>Gmail 已连接</h1><p>关闭此页面，回到邮件简报 App 点击“刷新连接状态”，即可开始整理。</p><p>你可随时在 Google 账号中撤销授权。</p></body></html>'
    class Schedule(BaseModel):
        time:str=Field(pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
        timezone:str='Asia/Shanghai'
        enabled:bool=True
    @app.put('/v1/schedule',dependencies=[Depends(auth)])
    async def schedule(value:Schedule):
        try:ZoneInfo(value.timezone)
        except Exception:raise HTTPException(422,'时区无效。') from None
        store.put('schedule',value.model_dump());return value
    class Push(BaseModel):token:str=Field(max_length=256)
    @app.put('/v1/push',dependencies=[Depends(auth)])
    async def push(value:Push):
        if not re.fullmatch(r'(Expo|Exponent)PushToken\[[A-Za-z0-9_-]+\]',value.token):raise HTTPException(422,'推送令牌格式不正确。')
        store.put('push',value.token);store.put('push_status','registered');return {'registered':True}
    @app.delete('/v1/push',dependencies=[Depends(auth)])
    async def remove_push():store.delete('push','push_pending','push_status');return {'registered':False}
    @app.delete('/v1/account',dependencies=[Depends(auth)])
    async def disconnect():
        async with lock:
            saved=store.get('google')
            if saved:
                try:
                    async with httpx.AsyncClient(timeout=20) as client:
                        r=await client.post('https://oauth2.googleapis.com/revoke',data={'token':saved['refresh_token']})
                        revoked=r.status_code in (200,400)
                except Exception:revoked=False
            else:revoked=True
            store.delete('translations','google','digests','watermark','push','push_pending','push_status','oauth','schedule_done','last_error','rules')
        return {'disconnected':True,'googleRevocationConfirmed':revoked}
    return app
