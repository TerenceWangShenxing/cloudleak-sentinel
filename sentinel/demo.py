from datetime import datetime, timezone, timedelta
import secrets
from .models import Artifact
from .engine import run

class _SyntheticSource:
    def __init__(self, scenario='cloud-pair'):
        self.scenario=scenario
    def collect(self):
        now=datetime.now(timezone.utc)
        published=(now-timedelta(seconds=1.2)).isoformat()
        token=secrets.token_hex(5).upper()
        base={
            'cloud-pair': f'HUAWEI_CLOUD_AK=AB12{token}IJ90\nHUAWEI_CLOUD_SK=Q9X7{token}mN5pR8sT2vW4yZ6aB1cD0fG2',
            'oauth': f'client_secret=LiveDemo{token}X9m2P6v4Q8',
            'database': f'postgresql://demo:Db{token}Q8v4@db.example.internal:5432/app',
            'token': f'api_key=DemoLive{token}x9Q7m2P8v4Z6',
        }
        content=base.get(self.scenario, base['cloud-pair'])
        yield Artifact(source='SyntheticDemoSource', locator=f'demo://scenario/{self.scenario}/{token}', content=content,
                       observed_at=now.isoformat(), published_at=published, channel='live-demo',
                       metadata={'synthetic':True,'scenario':self.scenario})

def inject(scenario='cloud-pair'):
    return run(_SyntheticSource(scenario), f'demo:{scenario}')
