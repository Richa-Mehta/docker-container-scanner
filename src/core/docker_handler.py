"""
docker_handler.py

Purpose:
---------
Handles all communication with the Docker Engine.

Responsibilities:
- Connect to Docker
- Pull/Get Docker Images
- Extract Image Metadata

Returns only Python dictionaries.
No printing.
No scoring.
No report generation.
"""

import docker
from docker.errors import DockerException, ImageNotFound


class DockerHandler:
    """
    Handles Docker Engine operations.
    """

    def __init__(self):
        self.client = None

    # --------------------------------------------------------
    # Connect to Docker
    # --------------------------------------------------------

    def connect(self):
        """
        Connect to the local Docker Engine.

        Returns
        -------
        bool
            True if connection successful.

        Raises
        ------
        DockerException
            If Docker is unavailable.
        """

        if self.client is None:
            self.client = docker.from_env()

            # Verify connection
            self.client.ping()

        return True

    # --------------------------------------------------------
    # Get Image
    # --------------------------------------------------------

    def get_image(self, reference):
        """
        Pull or retrieve a Docker image.

        Parameters
        ----------
        reference : str
            Example:
                nginx:latest
                python:3.12

        Returns
        -------
        docker.models.images.Image
        """

        self.connect()

        try:
            image = self.client.images.get(reference)

        except ImageNotFound:
            image = self.client.images.pull(reference)

        return image

    # --------------------------------------------------------
    # Metadata Extraction
    # --------------------------------------------------------

    def get_metadata(self, reference):
        """
        Extract metadata from a Docker image.

        Returns
        -------
        dict
        """

        image = self.get_image(reference)

        attrs = image.attrs

        repo_tags = attrs.get("RepoTags", [])

        image_name = reference.split(":")[0]

        tag = "latest"

        if ":" in reference:
            tag = reference.split(":")[1]

        architecture = attrs.get("Architecture")

        operating_system = attrs.get("Os")

        size = attrs.get("Size")

        created = attrs.get("Created")

        repo_digests = attrs.get("RepoDigests", [])

        digest = None

        if repo_digests:
            digest = repo_digests[0].split("@")[1]

        metadata = {
            "reference": reference,
            "name": image_name,
            "tag": tag,
            "os": operating_system,
            "architecture": architecture,
            "sizeBytes": size,
            "createdAt": created,
            "digest": digest,
            "source": "docker-engine"
        }

        return metadata