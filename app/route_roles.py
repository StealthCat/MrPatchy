"""Inventory of the role every HTTP route declares.

Roles are declared on each route through a role dependency (viewer, operator, admin or
self-service) and are never inferred from the request path. A route that declares no
role fails closed: the application refuses to start instead of exposing the route to
every signed-in viewer. Routes that are intentionally reachable without a session are
listed in PUBLIC_ROUTES, so adding one is a visible, reviewed decision.
"""
from fastapi.routing import APIRoute

# (method, path template) of routes that do not require a session.
PUBLIC_ROUTES=frozenset({
    ('GET','/'),('GET','/healthz'),('POST','/api/login'),('GET','/enroll/{token}'),
    ('GET','/api/sso'),('GET','/auth/sso'),('GET','/auth/sso/callback'),
})
# Mounts that serve static files only.
STATIC_MOUNTS=frozenset({'/static'})

def api_routes(routes):
    for route in routes:
        if isinstance(route,APIRoute): yield route
        elif hasattr(route,'original_router'): yield from api_routes(route.original_router.routes)
        elif getattr(route,'path',None) in STATIC_MOUNTS: continue
        else: raise RuntimeError('Route '+repr(getattr(route,'path',route))+' is neither an API route nor a known static mount; declare its role')

def declared_role(route,registry):
    """Return the single role a route declares, or None when it declares none."""
    roles={registry[d.call] for d in route.dependant.dependencies if d.call in registry}
    if len(roles)>1: raise RuntimeError('Route '+route.path+' declares conflicting roles: '+', '.join(sorted(roles)))
    return next(iter(roles),None)

def inventory(app,registry):
    """Map (method, path) -> declared role, or 'public' for allow-listed routes."""
    table={}
    for route in api_routes(app.router.routes):
        role=declared_role(route,registry)
        for method in sorted(route.methods-{'HEAD'}):
            key=(method,route.path)
            if role is None and key not in PUBLIC_ROUTES:
                raise RuntimeError('Route '+method+' '+route.path+' declares no role; add a role dependency or list it in PUBLIC_ROUTES')
            if role is not None and key in PUBLIC_ROUTES:
                raise RuntimeError('Route '+method+' '+route.path+' is public but also declares role '+role)
            table[key]=role or 'public'
    return table
