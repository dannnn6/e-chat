"""Actual Chromium smoke test. Start a disposable local E-chat server first.
ECHAT_SMOKE_URL defaults to http://127.0.0.1:18080; never point this at production.
Creates disposable accounts and messages. Does not save recovery keys or tokens in reports.
"""
import json
import os
import time
import uuid
from pathlib import Path
from playwright.sync_api import sync_playwright

URL=os.getenv('ECHAT_SMOKE_URL','http://127.0.0.1:18080')
INVITE=os.getenv('ECHAT_SMOKE_INVITE','browser-test-invite')
REPORT=Path(os.getenv('ECHAT_SMOKE_REPORT','reports/browser'))
REPORT.mkdir(parents=True,exist_ok=True)
results=[]
def check(name, fn):
    start=time.monotonic();fn();results.append({'check':name,'status':'passed','seconds':round(time.monotonic()-start,3)});print(name,'OK',flush=True)

def register(page, name):
    page.goto(URL)
    page.locator('#display-name').fill(name)
    page.locator('#registration-invite').fill(INVITE)
    page.locator('#auth-submit').click()
    page.locator('#dialog textarea').wait_for()
    code=page.locator('#dialog textarea').input_value()
    assert code.startswith('ECHAT1.')
    page.locator('#dialog input[type=checkbox]').check()
    page.get_by_role('button',name='Ключ сохранён, зарегистрироваться',exact=True).click()
    page.locator('#main').wait_for(state='visible',timeout=20000)
    page.wait_for_function('conversations.length>0')
    return page.evaluate('credentials.user.id'),code

with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=os.getenv('CHROMIUM') or None,headless=True)
    ca=browser.new_context(viewport={'width':1280,'height':850},accept_downloads=True)
    cb=browser.new_context(viewport={'width':1280,'height':850},accept_downloads=True)
    a,b=ca.new_page(),cb.new_page()
    errors=[]
    a.on('pageerror',lambda e:errors.append(str(e)));b.on('pageerror',lambda e:errors.append(str(e)))
    try:
        aid,root=register(a,'Алиса '+uuid.uuid4().hex[:5]);bid,_=register(b,'Борис '+uuid.uuid4().hex[:5])
        results.append({'check':'two independent browser registrations, Cyrillic signature binding','status':'passed'})
        a.bring_to_front();a.locator('#new-direct').click();a.locator('#dialog-body input').fill(bid)
        a.get_by_role('button',name='Продолжить',exact=True).click()
        a.wait_for_function('currentId!==null');cid=a.evaluate('currentId')
        a.locator('#message-input').fill('Привет из браузера');a.locator('#send').click()
        a.wait_for_function("document.querySelectorAll('.msg.pending').length===0 && [...visible.values()].some(m=>m.body==='Привет из браузера')",timeout=30000)
        b.bring_to_front();b.locator('[data-cid="'+cid+'"]').wait_for(timeout=35000);b.locator('[data-cid="'+cid+'"]').click()
        b.locator('.msg-body',has_text='Привет из браузера').wait_for(timeout=15000)
        results.append({'check':'direct conversation and visible recipient delivery','status':'passed'})
        a.bring_to_front();a.evaluate('navigator.serviceWorker.ready')
        ca.set_offline(True)
        a.locator('#message-input').fill('Пережить перезагрузку без сети');a.locator('#send').click()
        a.wait_for_function("document.querySelectorAll('.msg.pending').length===1")
        a.reload(wait_until='domcontentloaded');a.locator('#main').wait_for(state='visible')
        assert a.evaluate("all('outbox').then(x=>x.some(m=>m.body==='Пережить перезагрузку без сети'))")
        ca.set_offline(False)
        a.wait_for_function("all('outbox').then(x=>x.length===0)",timeout=35000)
        history=a.evaluate('(cid)=>rpc("history",{cid,limit:100})',cid)
        assert len([m for m in history['messages'] if m['body']=='Пережить перезагрузку без сети'])==1
        results.append({'check':'offline queue survives page reload, then sends exactly once','status':'passed'})
        a.locator('[data-cid="'+cid+'"]').click()
        a.wait_for_function('currentId!==null')
        dropped={'done':False}
        def lose_ack(route):
            response=route.fetch()
            if not dropped['done']:
                dropped['done']=True;route.abort('failed')
            else: route.fulfill(response=response)
        a.route('**/api/rpc?action=send',lose_ack)
        a.locator('#message-input').fill('Потерянный ACK не создаёт дубль');a.locator('#send').click()
        a.wait_for_function("all('outbox').then(x=>x.length===0)",timeout=35000)
        a.unroute('**/api/rpc?action=send',lose_ack)
        history=a.evaluate('(cid)=>rpc("history",{cid,limit:100})',cid)
        assert len([m for m in history['messages'] if m['body']=='Потерянный ACK не создаёт дубль'])==1
        results.append({'check':'server commits send, HTTP acknowledgement lost, no duplicate','status':'passed'})
        cdp=ca.new_cdp_session(a);cdp.send('Network.enable')
        cdp.send('Network.emulateNetworkConditions',{'offline':False,'latency':800,'downloadThroughput':2000,'uploadThroughput':1000,'connectionType':'cellular2g'})
        began=time.monotonic();a.locator('#message-input').fill('Текст через медленную сеть');a.locator('#send').click()
        a.wait_for_function("all('outbox').then(x=>x.length===0)",timeout=40000)
        elapsed=time.monotonic()-began
        results.append({'check':'warm client text at 16 kbit/s down, 8 kbit/s up, 800ms simulated latency','status':'passed','seconds':round(elapsed,3)})
        cdp.send('Network.emulateNetworkConditions',{'offline':False,'latency':0,'downloadThroughput':-1,'uploadThroughput':-1,'connectionType':'wifi'})
        a.locator('#files').set_input_files({'name':'notes.txt','mimeType':'text/plain','buffer':b'resumable browser attachment\n'*3000})
        a.locator('#message-input').fill('Вложение без автозагрузки');a.locator('#send').click()
        a.wait_for_function("all('outbox').then(x=>x.length===0)",timeout=35000)
        b.bring_to_front();b.locator('.msg-body',has_text='Вложение без автозагрузки').wait_for(timeout=35000)
        with b.expect_download() as d:
            b.get_by_role('button',name='↓ notes.txt',exact=False).click()
        downloaded=Path(d.value.path()).read_bytes();assert downloaded==b'resumable browser attachment\n'*3000
        results.append({'check':'browser attachment upload, recipient manual download and integrity check','status':'passed'})
        # New device recovery in an independent browser context.
        cr=browser.new_context(viewport={'width':390,'height':844});r=cr.new_page();r.goto(URL)
        r.locator('#tab-recover').click();r.locator('#recovery-input').fill(root);r.locator('#auth-submit').click()
        r.locator('#main').wait_for(state='visible',timeout=20000)
        assert r.evaluate('credentials.user.id')==aid
        r.locator('[data-cid="'+cid+'"]').wait_for(timeout=15000);r.locator('[data-cid="'+cid+'"]').click()
        r.locator('.msg-body',has_text='Привет из браузера').wait_for(timeout=15000)
        assert r.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        r.screenshot(path=str(REPORT/'mobile.png'),full_page=True)
        b.screenshot(path=str(REPORT/'desktop.png'),full_page=True)
        results.append({'check':'new browser device recovery retains ID and cloud history; mobile width 390px','status':'passed'})
        assert not errors,errors
        results.append({'check':'uncaught JavaScript errors','status':'passed','count':0})
    except Exception as exc:
        results.append({'check':'browser test exception','status':'failed','error':str(exc)})
        a.screenshot(path=str(REPORT/'failure.png'),full_page=True)
        raise
    finally:
        (REPORT/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
        browser.close()
print(json.dumps(results,ensure_ascii=False,indent=2))