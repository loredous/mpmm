import asyncio
import pytest
from mpmm_ax25.timer import Timer, TimerResult, TimerState

@pytest.mark.asyncio
async def test_timer_setup():
    # Arrange
    async def callback(timer, result):
        pass

    # Act
    timer = Timer(callback, timeout=10)

    # Assert
    assert timer.state == TimerState.STOPPED
    assert timer.timeout == 10

@pytest.mark.asyncio
async def test_timer_expiry():
    # Arrange
    global RESULT
    RESULT = {
        'callback_executed': False,
        'callback_timer': None,
        'callback_result': None
    }
    async def callback(timer, result):
        global RESULT
        RESULT['callback_executed'] = True
        RESULT['callback_timer'] = timer
        RESULT['callback_result'] = result

    timer = Timer(callback, timeout=0.1)

    # Act
    await timer.start()
    await asyncio.sleep(1)

    # Assert
    assert timer.state == TimerState.EXPIRED
    assert RESULT['callback_executed'] == True
    assert RESULT['callback_timer'] == timer
    assert RESULT['callback_result'] == TimerResult.EXPIRED

@pytest.mark.asyncio
async def test_timer_cancel():
    # Arrange
    global RESULT
    RESULT = {
        'callback_executed': False,
        'callback_timer': None,
        'callback_result': None
    }
    async def callback(timer, result):
        global RESULT
        RESULT['callback_executed'] = True
        RESULT['callback_timer'] = timer
        RESULT['callback_result'] = result

    timer = Timer(callback, timeout=30)

    # Act
    await timer.start()
    await timer.stop()

    # Assert
    assert timer.state == TimerState.STOPPED
    assert RESULT['callback_executed'] == True
    assert RESULT['callback_timer'] == timer
    assert RESULT['callback_result'] == TimerResult.CANCELLED