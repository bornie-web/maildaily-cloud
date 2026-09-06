"""Translate stored digest text only; preserve originals and mail links."""
import copy, hashlib, html, json
from datetime import datetime, timezone
import httpx
from fastapi import HTTPException
LANGUAGES={'zh-CN','zh-TW','en','ja','ko','fr','de','es','pt','it','ru','ar','hi','th','vi','id'}
async def translate_digest(store, digest, target, api_key):
    if target not in LANGUAGES: raise HTTPException(422,'暂不支持此翻译语言。')
    if not api_key: raise HTTPException(503,'云端尚未配置 GOOGLE_TRANSLATE_API_KEY，请先启用翻译服务。')
    cache=store.get('translations',{})
    key=hashlib.sha256((target+json.dumps(digest,sort_keys=True,ensure_ascii=False)).encode()).hexdigest()
    if key in cache:return cache[key]
    result=copy.deepcopy(digest)
    fields=[(result,'headline',2000)]
    for item in result['items']:
        fields.extend((item,k,limit) for k,limit in [('title',500),('summary',10000),('action',10000)])
    fields=[x for x in fields if x[0].get(x[1],'').strip()]
    texts=[obj[k] for obj,k,_ in fields]
    count=sum(map(len,texts))
    if count>50000:raise HTTPException(413,'本期内容过多，暂不翻译；原文仍可查看。')
    month=datetime.now(timezone.utc).strftime('%Y-%m')
    usage=store.get('translation_usage',{})
    used=usage.get('characters',0) if usage.get('month')==month else 0
    if used+count>300000:raise HTTPException(429,'已达到本应用每月30万字符的翻译限额，仍可查看原文。')
    # Reserve usage before sending, including failed attempts. Not a billing guarantee.
    store.put('translation_usage',{'month':month,'characters':used+count})
    output=[]
    batches=[];batch=[];size=0
    for text in texts:
        if batch and (len(batch)>=100 or size+len(text)>5000):batches.append(batch);batch=[];size=0
        batch.append(text);size+=len(text)
    if batch:batches.append(batch)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            for batch in batches:
                response=await client.post('https://translation.googleapis.com/language/translate/v2',
                    headers={'X-Goog-Api-Key':api_key},json={'q':batch,'target':target,'format':'text'})
                if response.status_code!=200:raise ValueError('provider rejected request')
                values=response.json()['data']['translations']
                if len(values)!=len(batch):raise ValueError('incomplete translation')
                for value in values:
                    text=value['translatedText']
                    if not isinstance(text,str):raise ValueError('invalid text')
                    output.append(html.unescape(text))
    except (httpx.HTTPError,KeyError,ValueError,TypeError):
        raise HTTPException(502,'翻译未完成，原文已保留。请检查翻译 API 的启用、密钥限制、结算和配额。') from None
    for (obj,k,limit),text in zip(fields,output):obj[k]=text[:limit]
    cache[key]=result
    store.put('translations',dict(list(cache.items())[-30:]))
    return result
