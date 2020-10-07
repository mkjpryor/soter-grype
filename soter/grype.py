"""
Module providing the ASGI app for soter-grype.
"""

import asyncio
import json
import logging
import os
import shlex

from quart import Quart

from jsonrpc.model import JsonRpcException

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint

from .scanner.models import ScannerStatus, Image, Severity, PackageType, ImageVulnerability


SCANNER_KIND = 'Grype'
SCANNER_VENDOR = 'Anchore'


# Configuration options
#: The grype command to use
GRYPE_COMMAND = os.environ.get('GRYPE_COMMAND', 'grype')
#: The number of concurrent scans to allow per worker
GRYPE_CONCURRENT_SCANS = int(os.environ.get('GRYPE_CONCURRENT_SCANS', '1'))


class GrypeError(JsonRpcException):
    """
    Raised when there is an error calling out to the Grype CLI.
    """
    message = "Grype error"
    code = 100


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
dispatcher = Dispatcher()
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')


logger = logging.getLogger(__name__)


@dispatcher.register
async def status():
    """
    Return status information for the scanner.
    """
    # First, get the grype version
    proc = await asyncio.create_subprocess_shell(
        f"{GRYPE_COMMAND} version --output json",
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode != 0:
        logger.error('Grype command failed: {}'.format(stderr_data.decode()))
        return ScannerStatus(
            kind = SCANNER_KIND,
            vendor = SCANNER_VENDOR,
            version = 'unknown',
            available = False,
            message = 'could not detect status'
        )
    version = json.loads(stdout_data)['version']
    # Then get the database status
    # Unfortunately, this is not available in JSON format so we have to do some parsing
    proc = await asyncio.create_subprocess_shell(
        f"{GRYPE_COMMAND} db status --quiet",
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode != 0:
        logger.error('Grype command failed: {}'.format(stderr_data.decode()))
        return ScannerStatus(
            kind = SCANNER_KIND,
            vendor = SCANNER_VENDOR,
            version = version,
            available = False,
            message = 'could not detect database status'
        )
    # Parse the output lines
    db_status = dict(line.split(':', maxsplit = 1) for line in stdout_data.decode().splitlines())
    return ScannerStatus(
        kind = 'Grype',
        vendor = 'Anchore',
        version = version,
        available = True,
        message = 'available',
        properties = {
            'vulnerabilitydb/status': db_status['Status'].strip(),
            'vulnerabilitydb/version': db_status['Require DB Version'].strip(),
            'vulnerabilitydb/built': db_status['Built'].strip(),
        }
    )


@app.before_serving
async def create_semaphore():
    """
    Create a semaphore that we will use to limit concurrency of scanning
    """
    app.scan_semaphore = asyncio.Semaphore(GRYPE_CONCURRENT_SCANS)


@dispatcher.register
async def scan_image(image):
    """
    Scans the given image and returns vulnerability information.
    """
    # Parse the image using the model
    image = Image.parse_obj(image)
    async with app.scan_semaphore:
        # Call out to Grype to scan the image
        proc = await asyncio.create_subprocess_shell(
            "{} {} --quiet --output json".format(GRYPE_COMMAND, shlex.quote(image.full_digest)),
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE
        )
        stdout_data, stderr_data = await proc.communicate()
    if proc.returncode != 0:
        raise GrypeError(stderr_data)
    result = json.loads(stdout_data)
    if result:
        return [
            ImageVulnerability(
                title = match['vulnerability']['id'],
                severity = Severity[match['vulnerability']['severity'].upper()],
                info_url = next(iter(match['vulnerability'].get('links', [])), None),
                package_name = match['artifact']['name'],
                package_version = match['artifact']['version'],
                # OS packages have "distro" in their search keys
                package_type = (
                    PackageType.OS
                    if 'distro' in match['matchDetails']['searchKey']
                    else PackageType.NON_OS
                ),
                package_location = (
                    next(iter(match['artifact']['locations']))['path']
                    if 'distro' not in match['matchDetails']['searchKey']
                    else None
                ),
                fix_version = match['vulnerability'].get('fixedInVersion')
            )
            for match in result.get('matches', [])
        ]
    else:
        return []
