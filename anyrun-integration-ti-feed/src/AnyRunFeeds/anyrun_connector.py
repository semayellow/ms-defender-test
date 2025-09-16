import json
import logging as log
import traceback

import azure.functions as func
from anyrun import RunTimeException

from .anyrunfeeds import AnyRunFeeds


def main(req: func.HttpRequest) -> func.HttpResponse:
    log.info('AnyRunFeeds started. Checking TI Feeds credentials...')

    try:
        feed_fetch_depth: int = req.params.get('feed_fetch_depth') or req.get_json().get('feed_fetch_depth')

        if not feed_fetch_depth:
            raise ValueError(
                f'The following parameters: feed_fetch_depth are required.'
            )

        feed_connector = AnyRunFeeds(log, feed_fetch_depth)
        feed_connector.process_enrichment()

        return func.HttpResponse(
            json.dumps({"message": "IOC enrichment successful."}),
            status_code=200,
        )

    except RunTimeException as error:
        return func.HttpResponse(str(error), status_code=500)
    except Exception:
        error_msg = traceback.format_exc()
        log.error(f'Unspecified exception occurred: {error_msg}')
        log.error(error_msg)
        return func.HttpResponse(f'Unspecified exception: {error_msg}', status_code=500)
