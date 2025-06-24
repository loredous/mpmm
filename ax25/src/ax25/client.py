import asyncio
from ax25.connection import AX25Connection
from kiss.client import KISSClient
from kiss.frame import KISSFrame


class AX25Client:
    _connections: list[AX25Connection] = []
    _clients: list[KISSClient] = []

    def add_client(self, client: KISSClient):
        client.decode_callback = self.handle_kiss_frame
        self._clients.append(client)
        
    async def handle_kiss_frame(self, frame: KISSFrame):
        print(f"Received KISS frame: {frame}")

    def run(self):
        loop = asyncio.get_event_loop()
        tasks = [client.start_listen() for client in self._clients]
        loop.run_until_complete(asyncio.gather(*tasks))
        loop.run_forever()

if __name__ == "__main__":
    client = AX25Client()
    kiss_client = None
    client.add_client(kiss_client)
    client.run()