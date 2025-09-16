import os


def get_env_variable(name: str) -> str:
    """
    Retrieves environment variable value

    :param name: Environment variable name
    :return: Environment variable value
    :raises ValueError: If variable is not set
    """
    if not (variable := os.environ.get(name)):
        raise ValueError(f'Environment variable {name} is not set.')
    return variable


def extract_indicator_data(pattern: str) -> tuple[str, str]:
    """
    Extracts indicator type, value using raw indicator

    :param pattern: STIX pattern
    :return: ANY.RUN indicator type, ANY.RUN indicator value
    """
    indicator_type = pattern.split(":")[0][1:]
    indicator_value = pattern.split(" = '")[1][:-2]

    return indicator_type, indicator_value


def get_severity(confidence: int) -> str:
    if confidence == 0:
        return 'Informational'
    elif 1 <= confidence < 50:
        return 'Low'
    elif 50 <= confidence < 100:
        return 'Medium'
    elif confidence == 100:
        return 'High'


def get_description(external_references: list[dict[str, str]]) -> str:
    if not external_references:
        return 'No description'
    return ','.join(reference.get('url') for reference in external_references[:9])
