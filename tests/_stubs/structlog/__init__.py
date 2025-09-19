class _StubLogger:
    def __init__(self, **context):
        self._context = context

    def bind(self, **new_context):
        merged = {**self._context, **new_context}
        return _StubLogger(**merged)

    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None

    def exception(self, *args, **kwargs):
        return None


def get_logger(*args, **kwargs):
    return _StubLogger()
