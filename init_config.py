from pathlib import Path
import secrets
from cryptography.fernet import Fernet
p=Path('.env')
if p.exists():raise SystemExit('.env 已存在，为避免覆盖你的密钥，未作修改。')
s=Path('.env.example').read_text()
s=s.replace('APP_API_KEY=\n','APP_API_KEY='+secrets.token_urlsafe(40)+'\n').replace('DATA_ENCRYPTION_KEY=\n','DATA_ENCRYPTION_KEY='+Fernet.generate_key().decode()+'\n')
p.write_text(s);p.chmod(0o600)
print('已生成 .env。请在本机编辑 Google 配置与域名；APP_API_KEY 填入你自己的手机 App。不要把密钥发到聊天中。')
