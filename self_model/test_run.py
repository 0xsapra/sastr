"""
    python3 run_model_x.py # this should be running
"""

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain.tools import tool

llm=ChatOpenAI(
    model="qwen-1.5b",
    api_key="dk",
    base_url="http://localhost:8000/v1"
)




@tool
def read_file(file_path: str) -> str:
    """
    Reads the content of a file and returns it as a string.
    Args:
        file_path (str): The absolute path to the file to be read.
    Returns:
        str: The content of the file.
    Example:
        read_file("/tmp/example.txt")
    """
    with open(file_path, "r") as file:
        return file.read()

agent = create_agent(llm, tools=[read_file], debug=True)
res = agent.invoke({"messages": [("user", "hi. read and gimme file contents of /Users/amansapra/Desktop/NCIIPC/sast-vuln/sastra/requirements.txt")]})
messages = res["messages"]

print(messages)