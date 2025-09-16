import os
import logging as log
import traceback
from json import dumps

import azure.functions as func
from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun import RunTimeException

from .defender import MicrosoftDefender
from .utils import get_env_variable, prepare_url_analysis_options, clear_indicators
from .config import Config


def main(req: func.HttpRequest) -> func.HttpResponse:
    log.info('AnyRunDefender started. Checking ANY.RUN Sandbox credentials...')

    with BaseSandboxConnector(api_key=get_env_variable('ANYRUN_API_KEY'), integration=Config.VERSION) as connector:
        connector.check_authorization()
        log.info('Successful credentials check.')

    try:
        alert_id = req.params.get('alert_id') or req.get_json().get('alert_id')
        alert_source = req.params.get('alert_source') or req.get_json().get('alert_source')
        machine_os_platform = req.params.get('machine_os_platform') or req.get_json().get('machine_os_platform')
        analysis_options = req.params.get('analysis_options') or req.get_json().get('analysis_options')

        if not any((alert_id, alert_source, machine_os_platform, analysis_options)):
            raise ValueError(
                f'The following parameters: alert_id, alert_source, machine_os_platform, analysis_options'
                f' are required.'
            )

        process_alert(alert_id, alert_source, machine_os_platform, analysis_options)
        return func.HttpResponse(
            dumps({"message": "Successfully submitted and enriched alert"}),
            status_code=200,
        )
    except RunTimeException as error:
        return func.HttpResponse(str(error), status_code=500)
    except Exception:
        error_msg = traceback.format_exc()
        log.error(f'Unspecified exception occurred: {error_msg}')
        log.error(error_msg)
        return func.HttpResponse(f'Unspecified exception: {error_msg}', status_code=500)


def process_alert(
    alert_id: str,
    alert_source: str,
    machine_os_platform: str,
    analysis_options: dict[str, str | int | bool]
) -> None:
    ms_defender = MicrosoftDefender(log)
    machine_id, evidences = ms_defender.get_evidences(alert_id, machine_os_platform)

    log.info(f'Found evidences: {evidences}\n')

    if alert_source == 'WindowsDefenderAtp':
        for filepath in evidences.get('filepaths'):
            log.info(f'Initialized evidence loading: {filepath}.')
            if file := ms_defender.download_file_from_machine(machine_id, filepath):
                log.info(f'Evidence is successfully downloaded: {filepath}')
                setup_anyrun_connector('file', alert_id, machine_os_platform, analysis_options, ms_defender, file, os.path.basename(filepath))
            else:
                message = f'Requested file: {filepath} was not found on the machine.'
                log.warning(message)
                ms_defender.add_comment(alert_id, message)

    elif alert_source == 'WindowsDefenderAv':
        ms_defender.upload_ps_script_to_library(machine_os_platform)
        ms_defender.execute_ps_script_on_machine(machine_id, machine_os_platform, evidences.get('filepaths'))

        for filename in evidences.get('filenames'):
            log.info(f'Initialized evidence loading: {filename}.')
            if file := ms_defender.download_file_from_storage(filename):
                setup_anyrun_connector('file', alert_id, machine_os_platform, analysis_options, ms_defender, file, filename)
            else:
                message = f'Requested file: {filename} was not found in the blob storage.'
                log.warning(message)
                ms_defender.add_comment(alert_id, message)

    for url in evidences.get('urls'):
        setup_anyrun_connector('url',  alert_id, machine_os_platform, analysis_options, ms_defender, url=url)


def setup_anyrun_connector(
    analysis_type: str,
    alert_id: str,
    machine_os_platform: str,
    analysis_options: dict[str, str | int | bool],
    ms_defender: MicrosoftDefender,
    file: bytes | None = None,
    filename: str | None = None,
    url: str | None = None
) -> None:
    if machine_os_platform == 'windows':
        log.info(f'Initialized ANY.RUN analysis using Windows VM')
        with SandboxConnector.windows(
                api_key=get_env_variable('ANYRUN_API_KEY'),
                integration=Config.VERSION
        ) as connector:
            process_analysis(
                analysis_type,
                alert_id,
                connector,
                analysis_options,
                ms_defender,
                file,
                filename,
                url
            )

    elif machine_os_platform == 'linux':
        log.info(f'Initialized ANY.RUN analysis using Linux VM')
        with SandboxConnector.linux(
                api_key=get_env_variable('ANYRUN_API_KEY'),
                integration=Config.VERSION
        ) as connector:
            process_analysis(
                analysis_type,
                alert_id,
                connector,
                analysis_options,
                ms_defender,
                file,
                filename,
                url
            )


def process_analysis(
        analysis_type: str,
        alert_id: str,
        connector: WindowsConnector | LinuxConnector,
        analysis_options: dict[str, str | int | bool],
        ms_defender: MicrosoftDefender,
        file: bytes | None = None,
        filename: str | None = None,
        url: str | None = None
) -> None:
        if analysis_type == 'file':
            analysis_options.pop('obj_ext_browser')
            task_uuid = connector.run_file_analysis(file_content=file, filename=filename, **analysis_options)
        else:
            analysis_options = prepare_url_analysis_options(analysis_options)
            task_uuid = connector.run_url_analysis(obj_url=url, **analysis_options)

        ms_defender.add_task_reference_comment(alert_id, filename or url, task_uuid=task_uuid)

        for status in connector.get_task_status(task_uuid):
            log.info(str(status))

        verdict = connector.get_analysis_verdict(task_uuid)
        indicators = connector.get_analysis_report(task_uuid, report_format='ioc')
        valid_indicators = clear_indicators(indicators)
        report = connector.get_analysis_report(task_uuid)

        if valid_indicators:
            ms_defender.submit_indicators(valid_indicators, task_uuid)
            ms_defender.add_ioc_comment(alert_id, valid_indicators)
        else:
            log.warning('Malicious/Suspicious indicators not found.')

        ms_defender.add_summary_comment(alert_id, filename or url, verdict, report)