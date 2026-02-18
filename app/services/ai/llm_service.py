from ibm_watsonx_ai.metanames import GenTextParamsMetaNames
from langchain_ibm import WatsonxLLM
from langchain_core.output_parsers import JsonOutputParser
from app.models import LLMRequest

def query_llm(llm_args: LLMRequest, parser_required = True):
    """
    Generates text using the WatsonxLLM based on the provided LLMRequest arguments.

    Args:
        llm_args (LLMRequest): Contains parameters such as model ID, prompt template and inputs.

    Returns:
        The generated output from the WatsonxLLM chain.
    """
    import os

    # Define parameters for the WatsonxLLM
    parameters = {
        GenTextParamsMetaNames.DECODING_METHOD: "sample",
        GenTextParamsMetaNames.MAX_NEW_TOKENS: int(os.getenv("WATSONX_MAX_NEW_TOKENS", "1000")),
        GenTextParamsMetaNames.MIN_NEW_TOKENS: 1,
        GenTextParamsMetaNames.TEMPERATURE: 0.7,
        GenTextParamsMetaNames.TOP_K: 50,
        GenTextParamsMetaNames.TOP_P: 1,
    }

    # Initialize WatsonxLLM with environment variables and the provided model ID
    watsonx_llm = WatsonxLLM(
        model_id=llm_args.modelId,
        url=os.getenv("WATSONX_URL"),
        apikey=os.getenv("WATSONX_API_KEY"),
        project_id=os.getenv("WATSONX_API_PROJECT_ID"),
        params=parameters,
        verbose=True
    )

    # Create a chain combining the prompt template, WatsonxLLM
    chain = llm_args.promptTemplate | watsonx_llm

    # Adds parser dynamically
    if parser_required:
        chain |= JsonOutputParser()

    # Execute the chain with the provided prompt inputs and return the result
    return chain.invoke(llm_args.promptInputs)