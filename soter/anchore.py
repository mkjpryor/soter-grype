"""
Module providing the ASGI app for soter-anchore.
"""

import asyncio
import logging
import os

import httpx

from quart import Quart

from jsonrpc.model import JsonRpcException

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint

from .scanner.models import ScannerStatus, Image, Severity, PackageType, ImageVulnerability


dispatcher = Dispatcher()


logger = logging.getLogger(__name__)


# Get the Anchore config from the environment
ANCHORE_URL = os.environ['ANCHORE_URL']
ANCHORE_USERNAME = os.environ['ANCHORE_USERNAME']
try:
    with open(os.environ['ANCHORE_PASSWORD_FILE']) as fh:
        ANCHORE_PASSWORD = fh.read()
except KeyError:
    ANCHORE_PASSWORD = os.environ['ANCHORE_PASSWORD']

ANCHORE_POLL_INTERVAL = float(os.environ.get('ANCHORE_POLL_INTERVAL', '2.0'))


def anchore_client():
    """
    Returns an httpx client configured to talk to the Anchore API.
    """
    return httpx.AsyncClient(
        base_url = ANCHORE_URL,
        auth = httpx.BasicAuth(ANCHORE_USERNAME, ANCHORE_PASSWORD)
    )


@dispatcher.register
async def status():
    """
    Return status information for the scanner.
    """
    try:
        # Pull credentials from the environment
        async with anchore_client() as client:
            # Fetch system and feeds information concurrently
            system, feeds = await asyncio.gather(
                client.get('/system'),
                client.get('/system/feeds')
            )
        system.raise_for_status()
        feeds.raise_for_status()
        # Get the availability and version from the analyzer state
        analyzer_state = next(
            state
            for state in system.json()['service_states']
            if state['servicename'] == 'analyzer'
        )
        version = analyzer_state['service_detail']['version']
        available = analyzer_state['status']
        message = analyzer_state['status_message']
        if available:
            properties = {
                # Use the last sync time of each group as a property
                f"{group['name']}/last-sync": group['last_sync']
                for feed in feeds.json() if feed['enabled']
                for group in feed['groups'] if group['enabled']
            }
        else:
            properties = None
    except:
        logger.exception('Error detecting Anchore state')
        version = 'unknown'
        available = False
        message = 'could not detect status'
        properties = None
    return ScannerStatus(
        kind = 'Anchore Engine',
        vendor = 'Anchore',
        version = version,
        available = available,
        message = message,
        properties = properties
    )


@dispatcher.register
async def scan_image(image):
    """
    Scans the given image and returns vulnerability information.
    """
    # Parse the given image using the model
    image = Image.parse_obj(image)
    async with anchore_client() as client:
        # First, submit the image
        response = await client.post(
            '/images',
            json = dict(
                image_type = "docker",
                source = dict(
                    digest = dict(
                        pullstring = image.full_digest,
                        tag = image.full_tag,
                        creation_timestamp_override = image.created.strftime('%Y-%m-%dT%H:%M:%SZ')
                    )
                )
            )
        )
        response.raise_for_status()
        # Keep checking until the analysis status becomes analyzed
        while True:
            analysis_status = response.json()[0]['analysis_status']
            if analysis_status == "analyzed":
                break
            await asyncio.sleep(ANCHORE_POLL_INTERVAL)
            response = await client.get(f'/images/{image.digest}')
            response.raise_for_status()
        # Once analysis is complete, fetch the vulnerabilities
        response = await client.get(f'/images/{image.digest}/vuln/all')
        response.raise_for_status()
    return [
        ImageVulnerability(
            title = vuln['vuln'],
            severity = Severity[vuln['severity'].upper()],
            info_url = vuln['url'],
            package_name = vuln['package_name'],
            package_version = vuln['package_version'],
            package_type = (
                PackageType.OS
                if vuln['package_path'] == "pkgdb"
                else PackageType.NON_OS
            ),
            package_location = (
                vuln['package_path']
                if vuln['package_path'] != "pkgdb"
                else None
            ),
            fix_version = vuln['fix'] if vuln['fix'] != "None" else None
        )
        for vuln in response.json()['vulnerabilities']
    ]


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')
