# tools.py
from langchain_core.tools import tool
from kismet_utils import survey_wifi

@tool
def survey_wifi_tool(kismet_session: requests.Session) -> str:
    """Surveys the wireless networks using Kismet and returns a list of dictionaries with ssid, security, signal, mac."""
    networks = survey_wifi(kismet_session)
    return str(networks)