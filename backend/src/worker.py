import json,logging,os,socket,threading,time,uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
from sqlalchemy import or_,select,update
from .database import Session
from .models import Audit,RiskAssessment,Observation
from .risk_service import queue
from .algorithm import classify
logging.basicConfig(level=logging.INFO)
log=logging.getLogger('worker')
WORKER_ID=f'{socket.gethostname()}-{os.getpid()}'
STUCK_SECONDS=float(os.getenv('RISK_STUCK_SECONDS','120'))        # running 超过该时长视为卡住，允许被接手
RESCAN_SECONDS=float(os.getenv('RISK_RESCAN_SECONDS','15'))       # 漏算 / 卡住扫描间隔
QUEUE_GRACE_SECONDS=float(os.getenv('RISK_QUEUE_GRACE_SECONDS','30'))  # queued 超过该时长仍未被消费视为漏算
ARTIFACTS_DIR=os.getenv('ARTIFACTS_DIR','/artifacts')
def now():return datetime.now(timezone.utc)
def claim(db,row_id):
    # 条件更新认领：只有仍是 queued 的单子才能被接手，并发认领只有一个成功。
    token=f'{WORKER_ID}:{uuid.uuid4().hex[:8]}'
    n=db.execute(update(RiskAssessment).where(RiskAssessment.id==row_id,RiskAssessment.status=='queued').values(status='running',claimed_by=token,claimed_at=now(),attempts=RiskAssessment.attempts+1)).rowcount
    db.commit()
    return token if n==1 else None
def process(row_id):
    with Session() as db:
        token=claim(db,row_id)
        if not token:return
        try:
            row=db.get(RiskAssessment,row_id)
            obs=db.get(Observation,row.observation_id)  # 沿用受理时的病害测量，不取复测后的最新观测
            predicted,metrics=classify(obs.humidity,obs.holes,obs.mold)
            Path(ARTIFACTS_DIR).mkdir(exist_ok=True)
            Path(f'{ARTIFACTS_DIR}/risk-{row_id}.json').write_text(json.dumps(metrics,ensure_ascii=False))
            outcome=dict(status='done',predicted=predicted,metrics=metrics,error='')
        except Exception as exc:
            log.exception('classify failed risk=%s',row_id);outcome=dict(status='failed',error=str(exc)[:200])
        # 仅当单子仍由本次认领持有才落库；超时被别人接手或已复核后，晚到的结果直接丢弃。
        n=db.execute(update(RiskAssessment).where(RiskAssessment.id==row_id,RiskAssessment.status=='running',RiskAssessment.claimed_by==token).values(**outcome)).rowcount
        db.commit()
        if not n:log.info('discard late result risk=%s',row_id)
def recover(db):
    # 找回两类单子：已受理但队列漏算的 queued、running 卡死超时的；done/reviewed/failed 一律保持原样。
    taken=[]
    grace=now()-timedelta(seconds=QUEUE_GRACE_SECONDS)
    cutoff=now()-timedelta(seconds=STUCK_SECONDS)
    stuck=or_(RiskAssessment.claimed_at.is_(None),RiskAssessment.claimed_at<cutoff)
    for rid in db.scalars(select(RiskAssessment.id).where(RiskAssessment.status=='queued',RiskAssessment.created<grace)):
        if db.execute(update(RiskAssessment).where(RiskAssessment.id==rid,RiskAssessment.status=='queued').values(recovered=True)).rowcount==1:taken.append(rid)
    for rid in db.scalars(select(RiskAssessment.id).where(RiskAssessment.status=='running',stuck)):
        if db.execute(update(RiskAssessment).where(RiskAssessment.id==rid,RiskAssessment.status=='running',stuck).values(status='queued',claimed_by=None,claimed_at=None,recovered=True)).rowcount==1:taken.append(rid)
    for rid in taken:
        db.add(Audit(actor='worker',action='分级异常接手',detail=f'risk#{rid} 重新入队，沿用受理观测重算'))
        queue.rpush('folio:risk',rid)
    if taken:log.info('recovered risks %s',taken)
def reaper():
    while True:
        try:
            with Session() as db:recover(db);db.commit()
        except Exception:log.exception('recover iteration')
        time.sleep(RESCAN_SECONDS)
def main():
    threading.Thread(target=reaper,daemon=True).start()
    while True:
        Path('/tmp/worker-heartbeat').touch()
        try:
            item=queue.blpop('folio:risk',timeout=2)
            if item:process(int(item[1]))
        except Exception:logging.exception('worker iteration');time.sleep(1)
if __name__=='__main__':main()
