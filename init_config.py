from pathlib import Path
from urllib.parse import quote
import secrets
from cryptography.fernet import Fernet
p=Path('.env')
if not p.exists():
    s=Path('.env.example').read_text()
    s=s.replace('APP_API_KEY=\n','APP_API_KEY='+secrets.token_urlsafe(40)+'\n').replace('DATA_ENCRYPTION_KEY=\n','DATA_ENCRYPTION_KEY='+Fernet.generate_key().decode()+'\n')
    p.write_text(s);p.chmod(0o600)
    print('已生成 .env。请在本机编辑 Google 配置与域名；APP_API_KEY 填入你自己的手机 App。不要把密钥发到聊天中。')
else:
    print('.env 已存在，未作修改。')
values={}
for line in p.read_text().splitlines():
    if '=' in line and not line.startswith('#'):
        k,v=line.split('=',1);values[k.strip()]=v.strip()
base=values.get('PUBLIC_BASE_URL','').rstrip('/');key=values.get('APP_API_KEY','')
if base.startswith('https://') and len(key)>=32:
    link='maildaily://connect?base='+quote(base,safe='')+'&key='+quote(key,safe='')
    print('\n手机一键配置链接（在 App 设置页粘贴，或在手机浏览器/备忘录中点开）：')
    print(link)
    print('\n此链接包含连接密钥，只发给你自己的手机，不要发到群聊或交给他人。')
else:
    print('\n请先在 .env 中填好 PUBLIC_BASE_URL 后重新运行本脚本，即可生成一键配置链接。')
