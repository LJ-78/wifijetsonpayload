# graph.py
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage
from kismet_utils import survey_wifi
from analysis import find_easiest_and_hardest, select_network_for_crack, select_from_all_networks
import inquirer
from aircrack_module import AircrackManager
import requests
import sys

class State(TypedDict):
    messages: Annotated[list, add_messages]
    kismet_session: requests.Session
    networks: list
    analysis: dict
    selected_network: dict = None
    crack_result: dict = None

def survey_node(state: State):
    networks = survey_wifi(state["kismet_session"])
    return {"networks": networks, "messages": state["messages"] + [AIMessage(content=f"Surveyed {len(networks)} networks")]}

def analyze_node(state: State):
    easiest, hardest = find_easiest_and_hardest(state["networks"])
    analysis = {"easiest": easiest, "hardest": hardest}
    return {"analysis": analysis, "messages": state["messages"] + [AIMessage(content=f"Analysis complete")]}

def select_crack_node(state: State):
    # First ask if they want analyzed options or full list
    print("\n" + "="*50)
    print("NETWORK SELECTION")
    print("="*50)
    
    questions = [
        inquirer.List('choice',
                    message="How would you like to select a network?",
                    choices=[
                        "View analyzed options (easiest/hardest)",
                        "View full network list",
                        ">>> QUIT <<<"
                    ],
                    carousel=True)
    ]
    
    answers = inquirer.prompt(questions)
    
    if answers is None or answers['choice'] == ">>> QUIT <<<":
        print("\n[!] Selection cancelled. Exiting...")
        sys.exit(0)
    
    # Based on choice, show appropriate networks
    if answers['choice'] == "View analyzed options (easiest/hardest)":
        selected = select_network_for_crack(state["analysis"])
    else:  # Full network list
        selected = select_from_all_networks(state["networks"])
    
    print(selected)
    return {"selected_network": selected, "messages": state["messages"] + [AIMessage(content=f"Selected: {selected['ssid']}")]}

def crack_node(state: State):
    aircrack = AircrackManager()
    # if aircrack.check_prerequisites():
    if aircrack.capture_handshake(state["selected_network"]):
        result = aircrack.crack_with_aircrack(state["selected_network"])
        aircrack.cleanup()
        return {"crack_result": result, "messages": state["messages"] + [AIMessage(content=f"Crack result: {result.output}")]}

def build_graph():
    graph_builder = StateGraph(State)
    
    graph_builder.add_node("survey", survey_node)
    graph_builder.add_node("analyze", analyze_node)
    graph_builder.add_node("select_crack", select_crack_node)
    graph_builder.add_node("crack", crack_node)
    
    graph_builder.add_edge(START, "survey")
    graph_builder.add_edge("survey", "analyze")
    graph_builder.add_edge("analyze", "select_crack")
    graph_builder.add_edge("select_crack", "crack")
    graph_builder.add_edge("crack", END)
    
    return graph_builder.compile()













