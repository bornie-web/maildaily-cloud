"""Optional AI-written one-line summaries via DeepSeek; rule excerpts remain the fallback.

Enabled only when AI_SUMMARY is truthy and DEEPSEEK_API_KEY is configured.
Failures never fail the sync: callers keep the rule-based digest.
"""
import json
import httpx
SUMMARY_URL='https://api.deepseek.com/chat/completions'
def ai_summary_config(env):
    if (env('AI_SUMMARY') or '').strip().lower() not in ('1','true','yes','on'):return None
    key=(env('DEEPSEEK_API_KEY') or '').strip()
    if not key:return None
    return {'key':key,'model':(env('DEEPSEEK_MODEL') or 'deepseek-chat').strip() or 'deepseek-chat'}
def _chunked(items,size=40):
    for i in range(0,len(items),size):yield items[i:i+size]
async def apply_ai_summary(digest, cfg):
    """Rewrite item summaries with one-line AI summaries. Returns True when applied."""
    if not cfg:return False
    targets=[i for i in digest.get('items',[]) if i.get('count',1)==1 and i.get('summary') and i.get('id')!='promotions']
    if not targets:return False
    applied=False
    async with httpx.AsyncClient(timeout=90) as client:
        for group in _chunked(targets):
            payload=[{'title':i['title'][:200],'excerpt':i['summary'][:800]} for i in group]
            prompt=(
                '你是邮件摘要引擎。逐条为下列邮件写一句不超过60字的摘要，'
                '使用与邮件正文相同的语言，只说这封邮件要告诉读者什么、需要做什么（如有）。'
                '不要评论、不要编号以外的内容。返回 JSON {"summaries":[...]}，'
                '数量必须恰好为 '+str(len(group))+'，顺序一致。')
            response=await client.post(SUMMARY_URL,
                headers={'Authorization':'Bearer '+cfg['key']},
                json={'model':cfg['model'],'messages':[{'role':'system','content':'只输出合法 JSON。'},{'role':'user','content':prompt+'\n'+json.dumps(payload,ensure_ascii=False)}],'response_format':{'type':'json_object'},'temperature':0.2,'stream':False})
            if response.status_code!=200:raise ValueError('provider rejected request')
            values=json.loads(response.json()['choices'][0]['message']['content']).get('summaries')
            if not isinstance(values,list) or len(values)!=len(group) or not all(isinstance(x,str) for x in values):
                raise ValueError('incomplete summaries')
            for item,text in zip(group,values):
                text=' '.join(text.split())[:200]
                if text:item['summary']=text;item['aiSummary']=True;applied=True
    return applied
