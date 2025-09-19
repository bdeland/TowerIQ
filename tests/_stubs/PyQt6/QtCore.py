class QObject:
    def __init__(self, *args, **kwargs):
        super().__init__()


def pyqtSignal(*args, **kwargs):
    class _Signal:
        def __init__(self):
            self._callbacks = []

        def connect(self, callback):
            self._callbacks.append(callback)

        def emit(self, *args, **kwargs):
            for callback in list(self._callbacks):
                callback(*args, **kwargs)

    return _Signal()


class QMutex:
    def lock(self):
        return None

    def unlock(self):
        return None


class QMutexLocker:
    def __init__(self, mutex):
        self._mutex = mutex
        lock = getattr(self._mutex, "lock", None)
        if callable(lock):
            lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        unlock = getattr(self._mutex, "unlock", None)
        if callable(unlock):
            unlock()
        return False
