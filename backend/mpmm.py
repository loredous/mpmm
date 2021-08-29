from fastapi import Depends, FastAPI
from fastapi.param_functions import Body
from models.station import Station

api = FastAPI(title="Modern Packet Message Manager")


def get_station():
    # TODO: Proper storage and management of our station config and data.
    our_station = Station(
        callsign="",
        location="",
        locator=""
    )
    return our_station


@api.get('/station')
def get_station_config(station=Depends(get_station)):
    return station.get_base_config()


@api.post('/station')
def update_station_config(
    callsign: str = Body(default=None),
    location: str = Body(default=None),
    locator: str = Body(default=None),
    station=Depends(get_station)
):
    if callsign:
        station.callsign = callsign
    if location:
        station.location = location
    if locator:
        station.locator = locator
    return station.get_base_config()
