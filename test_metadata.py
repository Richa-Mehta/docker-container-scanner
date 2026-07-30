from pprint import pprint

from src.core.docker_handler import DockerHandler

handler = DockerHandler()

metadata = handler.get_metadata("nginx:latest")

pprint(metadata)