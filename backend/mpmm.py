from fastapi import FastAPI
from models.station import Station

api = FastAPI()


class mpmmAPI():

    def __init__(self) -> None:
        self.station = Station()

    @api.get('/station')
    def get_station_config(self):
        return self.station


instance = mpmmAPI()
