"""
Central LLM Client for SASTRA agent
Handles all LLM API calls with consistent configuration
"""
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from typing import List, Dict, Any, Optional


def get_langchain_llm(llm_config):
    """
    Get LangChain-compatible LLM client
    
    Args:
        llm_config: LLM configuration dictionary
        
    Returns:
        LangChain LLM instance configured with settings
    """
    if 'LLM_TYPE' not in llm_config:
        raise ValueError("LLM configuration missing 'LLM_TYPE' in model_config")
    
    LLM_TYPE = llm_config['LLM_TYPE'].lower()

    if LLM_TYPE == 'litellm': 
        if 'PROVIDER' not in llm_config or llm_config['PROVIDER'].lower() == 'openai':
            return ChatOpenAI(
                model=llm_config['MODEL'],
                api_key=llm_config['API_KEY'],
                base_url=llm_config.get('BASE_URL', None),
                temperature=0,
            )
        else:
            raise ValueError(f"Unsupported PROVIDER {llm_config['PROVIDER']} for LITELLM")
    
    elif LLM_TYPE == 'openai':
        return ChatOpenAI(
            model=llm_config['MODEL'],
            api_key=llm_config['API_KEY'],
            temperature=0,
        )
    
    elif LLM_TYPE == 'ollama':
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=llm_config['MODEL'],
            base_url=llm_config['BASE_URL'],
            temperature=0,
        )
    
    elif LLM_TYPE == 'anthropic' or LLM_TYPE == 'claude':
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=llm_config['MODEL'],
            api_key=llm_config['API_KEY'],
            temperature=0,
        )
    elif LLM_TYPE == 'gemini':
        from langchain_gemini import ChatGemini
        return ChatGemini(
            model=llm_config['MODEL'],
            api_key=llm_config['API_KEY'],
            temperature=0,
        )
    else:
        raise ValueError(f"Unsupported LLM type: {LLM_TYPE}. Supported: LITELLM, OPENAI, OLLAMA, ANTHROPIC")

