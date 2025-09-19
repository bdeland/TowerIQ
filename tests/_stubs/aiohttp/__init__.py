class ClientSession:  # pragma: no cover - stub implementation
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    async def get(self, *args, **kwargs):
        return _StubResponse()


class _StubResponse:
    async def text(self):  # pragma: no cover
        return ""

    async def json(self):  # pragma: no cover
        return {}
