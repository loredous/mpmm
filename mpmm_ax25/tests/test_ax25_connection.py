import asyncio
import pytest
from mpmm_ax25.ax25_connection import AX25Connection, AX25ConnectionState
from mpmm_ax25.ax25_frame import AX25Address, AX25AddressField, AX25ControlField, AX25Frame, AX25FrameType, AX25Modulo
from mpmm_ax25.timer import TimerState
from hypothesis import given, note, strategies as st

@pytest.mark.asyncio
async def test_create_ax25_connection():
    # Arrange
    local_address = AX25Address(callsign="K0JLB", ssid="9")

    # Act
    conn = AX25Connection(local_address=local_address)

    # Assert
    assert isinstance(conn, AX25Connection)
    assert conn.local_address == local_address
    assert conn.state == AX25ConnectionState.DISCONNECTED

@pytest.fixture
async def ax25_connection():
    local_address = AX25Address(callsign="K0JLB", ssid="9")
    return AX25Connection(local_address=local_address)

## Disconnected Frame Handler Tests

@pytest.mark.asyncio
async def test_basic_connection_setup(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABM | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.CONNECTED
    assert ax25_connection.remote_address == remote_address
    assert ax25_connection._keepalive_timer.state == TimerState.RUNNING
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_UA | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_connection_setup_modulo_mismatch_sabme(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.modulo = AX25Modulo.MOD_8
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabme_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABME | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabme_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.DISCONNECTED
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_connection_setup_modulo_mismatch_sabm(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.modulo = AX25Modulo.MOD_128
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabme_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABM | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabme_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.DISCONNECTED
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_disconnected_UI_handling_poll(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ui_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UI | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ui_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_disconnected_UI_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ui_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UI | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ui_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert len(recieved_frames) == 0

@pytest.mark.asyncio
async def test_disconnected_DISC_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    disc_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_DISC | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(disc_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME
    assert recieved_frames[0].control_field.poll_final == True

## Awaiting Connection Frame Handler Tests

@pytest.mark.asyncio
async def test_awaiting_connection_sabm_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABM | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_CONNECTION
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_UA | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_awaiting_connection_sabme_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABME | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_CONNECTION
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_awaiting_connection_disc_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_DISC | AX25FrameType.U_FRAME, poll_final=False), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_CONNECTION
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME

@pytest.mark.asyncio
async def test_awaiting_connection_ui_handling(ax25_connection):
    # Arrange
    global HANDLER_OUTPUT
    HANDLER_OUTPUT = []
    async def ui_handler(frame):
        global HANDLER_OUTPUT
        HANDLER_OUTPUT.append(frame)

    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    ax25_connection.add_ui_handler(ui_handler)
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ui_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UI | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ui_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_CONNECTION
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME
    assert len(HANDLER_OUTPUT) == 1
    assert HANDLER_OUTPUT[0] == ui_frame

@pytest.mark.asyncio
async def test_awaiting_connection_dm_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    dm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_DM | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(dm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.DISCONNECTED
    assert len(recieved_frames) == 0
    assert ax25_connection._outstanding_i_frame_timer.state != TimerState.RUNNING

@pytest.mark.asyncio
async def test_awaiting_connection_ua_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_CONNECTION
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ua_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UA | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ua_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.CONNECTED
    assert len(recieved_frames) == 0

## Awaiting Release Frame Handler Tests

@pytest.mark.asyncio
async def test_awaiting_release_sabm_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    sabm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_SABM | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(sabm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_RELEASE
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME
    assert recieved_frames[0].control_field.poll_final == True

@pytest.mark.asyncio
async def test_awaiting_release_disc_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    disc_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_DISC | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(disc_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_RELEASE
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_UA | AX25FrameType.U_FRAME
    assert recieved_frames[0].control_field.poll_final == True

@pytest.mark.asyncio
async def test_awaiting_release_ui_handling(ax25_connection):
    # Arrange
    global HANDLER_OUTPUT
    HANDLER_OUTPUT = []
    async def ui_handler(frame):
        global HANDLER_OUTPUT
        HANDLER_OUTPUT.append(frame)

    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    ax25_connection.add_ui_handler(ui_handler)
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ui_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UI | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ui_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_RELEASE
    assert len(recieved_frames) == 1
    assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME
    assert len(HANDLER_OUTPUT) == 1
    assert HANDLER_OUTPUT[0] == ui_frame

@pytest.mark.asyncio
@given(frame_type=st.sampled_from((AX25FrameType.SUP_REJ, AX25FrameType.SUP_RNR, AX25FrameType.SUP_RR, AX25FrameType.SUP_SREJ)),pf=st.booleans())
async def test_awaiting_release_s_handling(frame_type,pf):
    # Arrange
    local_address = AX25Address(callsign="K0JLB", ssid="9")
    ax25_connection = AX25Connection(local_address=local_address)
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    s_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=frame_type | AX25FrameType.S_FRAME, poll_final=pf), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(s_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.AWAITING_RELEASE
    if pf:
        assert len(recieved_frames) == 1
        assert recieved_frames[0].control_field.frame_type == AX25FrameType.UNN_DM | AX25FrameType.U_FRAME
    else:
        assert len(recieved_frames) == 0

@pytest.mark.asyncio
async def test_awaiting_release_ua_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    ua_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_UA | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(ua_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.DISCONNECTED
    assert len(recieved_frames) == 0

@pytest.mark.asyncio
async def test_awaiting_release_dm_handling(ax25_connection):
    # Arrange
    ax25_connection = await ax25_connection
    ax25_connection.state = AX25ConnectionState.AWAITING_RELEASE
    remote_address = AX25Address(callsign="NOCALL", ssid="15")
    local_address = ax25_connection.local_address
    dm_frame = AX25Frame(address_field=AX25AddressField(source=remote_address, destination=local_address), control_field=AX25ControlField(frame_type=AX25FrameType.UNN_DM | AX25FrameType.U_FRAME, poll_final=True), pid=0)

    # Act
    await ax25_connection.handle_ax25_frame(dm_frame)
    await asyncio.sleep(0.1)
    recieved_frames = [ax25_connection.outgoing_frames.get_nowait() for _ in range(ax25_connection.outgoing_frames.qsize())]

    # Assert
    assert ax25_connection.state == AX25ConnectionState.DISCONNECTED
    assert len(recieved_frames) == 0

## Connected Frame Handler Tests