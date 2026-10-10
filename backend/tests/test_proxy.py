import asyncio
import pytest
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

@pytest.mark.parametrize('peer,forwarded,expected', [
    ('169.254.169.126', '198.51.100.99, 192.0.2.25', '192.0.2.25'),
    ('169.254.169.126', '198.51.100.99, 192.0.2.25, 169.254.169.126', '192.0.2.25'),
    ('192.0.2.5', '198.51.100.99', '192.0.2.5'),
])
def test_only_known_ingress_can_supply_client_ip(peer, forwarded, expected):
    observed = []
    async def endpoint(scope, receive, send):
        observed.append(scope['client'][0])
    middleware = ProxyHeadersMiddleware(endpoint, trusted_hosts='127.0.0.1,169.254.169.126')
    scope = {'type': 'http', 'client': (peer, 1234), 'headers': [(b'x-forwarded-for', forwarded.encode())], 'scheme': 'http'}
    asyncio.run(middleware(scope, None, None))
    assert observed == [expected]
