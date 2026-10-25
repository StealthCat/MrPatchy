"""Bound request bodies before parsing, including chunked HTTP requests."""
from starlette.responses import JSONResponse

class RequestSizeLimit:
    def __init__(self, app, limit=4_000_000):
        self.app=app
        self.limit=limit

    async def __call__(self, scope, receive, send):
        if scope['type']!='http':
            return await self.app(scope,receive,send)
        headers=dict(scope.get('headers',[]))
        try:
            declared=int(headers.get(b'content-length',b'0'))
            if declared<0: raise ValueError()
        except ValueError:
            return await JSONResponse({'detail':'Invalid Content-Length'},status_code=400)(scope,receive,send)
        if declared>self.limit:
            return await JSONResponse({'detail':'Request too large'},status_code=413)(scope,receive,send)
        body=bytearray();size=0
        while True:
            message=await receive()
            if message['type']=='http.disconnect': return
            size+=len(message.get('body',b''))
            if size>self.limit:
                return await JSONResponse({'detail':'Request too large'},status_code=413)(scope,receive,send)
            body.extend(message.get('body',b''))
            if not message.get('more_body',False): break
        messages=[{'type':'http.request','body':bytes(body),'more_body':False}]
        async def replay():
            if messages: return messages.pop(0)
            return await receive()
        await self.app(scope,replay,send)
