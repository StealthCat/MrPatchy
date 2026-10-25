import asyncio
from app.http_security import RequestSizeLimit

def test_chunked_bodies_are_bounded_without_content_length():
    called=[];sent=[]
    async def inner(scope,receive,send): called.append(1)
    messages=iter([{'type':'http.request','body':b'123','more_body':True},{'type':'http.request','body':b'456','more_body':False}])
    async def receive(): return next(messages)
    async def send(message): sent.append(message)
    asyncio.run(RequestSizeLimit(inner,limit=5)({'type':'http','headers':[]},receive,send))
    assert not called and sent[0]['status']==413

def test_body_limit_accepts_and_replays_valid_chunks():
    seen=[]
    async def inner(scope,receive,send): seen.append(await receive())
    messages=iter([{'type':'http.request','body':b'12','more_body':True},{'type':'http.request','body':b'34','more_body':False}])
    async def receive(): return next(messages)
    async def send(message): pass
    asyncio.run(RequestSizeLimit(inner,limit=5)({'type':'http','headers':[]},receive,send))
    assert seen==[{'type':'http.request','body':b'1234','more_body':False}]
