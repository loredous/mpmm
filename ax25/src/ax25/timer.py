from asyncio import Task, get_running_loop, AbstractEventLoop, sleep
from enum import Enum
from collections.abc import Coroutine
from typing import Awaitable, Callable

class TimerError(Exception):
    pass

class TimerResult(Enum):
    EXPIRED = 0
    CANCELLED = 1
    ERROR = 2

class TimerState(Enum):
    STOPPED = 0
    RUNNING = 1
    EXPIRED = 2

class Timer:
    def __init__(self, callback: Callable[["Timer", TimerResult],Awaitable[None]], loop: AbstractEventLoop | None = None, timeout: float = 0):
        self._loop = loop or get_running_loop()
        self._task: Task | None = None
        self._timeout = timeout
        self._callback = callback
        self._state = TimerState.STOPPED

    @property
    def state(self):
        return self._state
    
    @property
    def timeout(self):
        return self._timeout
    
    @timeout.setter
    def timeout(self, value: int):
        if self._state == TimerState.RUNNING:
            raise TimerError("Cannot change timeout while timer is running")
        self._timeout = value

    async def _on_expire(self):
        self._state = TimerState.EXPIRED
        await self._callback(self, TimerResult.EXPIRED)

    async def start(self):
        if self._state == TimerState.RUNNING:
            raise TimerError("Timer already running")
        self._state = TimerState.RUNNING
        self._task = self._loop.create_task(self._run())
        

    async def _run(self):
        await sleep(self._timeout)
        await self._on_expire()

    async def stop(self):
        if self._state == TimerState.STOPPED:
            raise TimerError("Timer already stopped")
        if self._task:
            self._task.cancel()
        await self._callback(self, TimerResult.CANCELLED)
        self._state = TimerState.STOPPED
        