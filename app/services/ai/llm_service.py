from ibm_watsonx_ai.metanames import GenTextParamsMetaNames
from langchain_ibm import WatsonxLLM
from langchain_core.prompts import PromptTemplate
from typing import Dict, Any
import os

def query_llm(model_id: str, prompt_template: PromptTemplate, prompt_inputs: Dict[str, Any], 
              max_tokens: int = 2000, temperature: float = 0.3) -> str:
    """
    Query WatsonX LLM with the given prompt.
    
    Args:
        model_id: WatsonX model ID
        prompt_template: LangChain prompt template
        prompt_inputs: Dictionary of inputs for the prompt
        max_tokens: Maximum tokens to generate
        temperature: Temperature for generation
    
    Returns:
        str: Generated text from the LLM
    """
    # Define parameters for the WatsonxLLM
    parameters = {
        GenTextParamsMetaNames.DECODING_METHOD: "sample",
        GenTextParamsMetaNames.MAX_NEW_TOKENS: max_tokens,
        GenTextParamsMetaNames.MIN_NEW_TOKENS: 1,
        GenTextParamsMetaNames.TEMPERATURE: temperature,
        GenTextParamsMetaNames.TOP_K: 50,
        GenTextParamsMetaNames.TOP_P: 1,
    }

    # Initialize WatsonxLLM
    watsonx_llm = WatsonxLLM(
        model_id=model_id,
        url=os.getenv("WATSONX_URL"),
        apikey=os.getenv("WATSONX_API_KEY"),
        project_id=os.getenv("WATSONX_API_PROJECT_ID"),
        params=parameters,
        verbose=True
    )

    # Create chain and invoke
    chain = prompt_template | watsonx_llm
    return chain.invoke(prompt_inputs)

# Made with Bob
