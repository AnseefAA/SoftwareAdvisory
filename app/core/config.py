LLM_MODELS = ['codellama/codellama-34b-instruct-hf', 'google/flan-t5-xl', 'google/flan-t5-xxl', 'google/flan-ul2', 'ibm/granite-13b-chat-v2', 'ibm/granite-13b-instruct-v2', 'ibm/granite-20b-code-instruct', 'ibm/granite-20b-multilingual', 'ibm/granite-3-2b-instruct', 'ibm/granite-3-8b-instruct', 'ibm/granite-34b-code-instruct', 'ibm/granite-3b-code-instruct', 'ibm/granite-7b-lab', 'ibm/granite-8b-code-instruct', 'ibm/granite-8b-japanese-v2-rc', 'ibm/granite-guardian-3-2b', 'ibm/granite-guardian-3-8b', 'meta-llama/llama-2-13b-chat', 'meta-llama/llama-3-1-70b-instruct', 'meta-llama/llama-3-1-8b-instruct', 'meta-llama/llama-3-2-11b-vision-instruct', 'meta-llama/llama-3-2-1b-instruct', 'meta-llama/llama-3-2-3b-instruct', 'meta-llama/llama-3-2-90b-vision-instruct', 'meta-llama/llama-3-3-70b-instruct', 'meta-llama/llama-3-405b-instruct', 'meta-llama/llama-3-70b-instruct', 'meta-llama/llama-3-8b-instruct', 'meta-llama/llama-guard-3-11b-vision', 'mistralai/mistral-large', 'mistralai/mixtral-8x7b-instruct-v01']

# Logging Configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "default",
            "filename": "app.log",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"],
    },
    "loggers": {
        "uvicorn": {
            "level": "INFO",
            "handlers": ["console", "file"],
            "propagate": False,
        },
        "myapp": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
            "propagate": False,
        },
    },
}
