import asyncio, base64, hashlib, hmac, json, logging, os, re, secrets, time
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo
import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from core import Store, digest_query, organize
load_dotenv()
log=logging.getLogger('maildaily')
SCOPES='https://www.googleapis.com/auth/gmail.readonly'
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
                messages=await fetch_mail(start,end);digest=organize(messages,start,end)
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
        return {'connected':bool(g),'account':g.get('email'),'schedule':store.get('schedule',{'time':'19:00','timezone':'Asia/Shanghai','enabled':True}),'lastError':store.get('last_error'),'pushRegistered':bool(store.get('push')),'pushStatus':store.get('push_status','not_configured'),'summaryMode':'规则归类与正文摘录'}
    @app.get('/v1/digests',dependencies=[Depends(auth)])
    async def digests():
        pref=store.get('schedule',{'time':'19:00','timezone':'Asia/Shanghai','enabled':True})
        return {'account':store.get('google',{}).get('email',''),'scheduleLabel':'每天 '+pref['time'],'digests':store.get('digests',[])}
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
            store.delete('google','digests','watermark','push','push_pending','push_status','oauth','schedule_done','last_error')
        return {'disconnected':True,'googleRevocationConfirmed':revoked}
    return app
