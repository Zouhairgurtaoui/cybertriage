import httpx
from langchain_core.embeddings import Embeddings
from langchain_ollama import OllamaEmbeddings
from cybertriage.adapters.configuration.ollama_environment import ollama_base_url

from cybertriage.adapters.models.runtime import model_http_timeout

class RunbookEmbeddings(Embeddings):
    def __init__(self):
        self.model = OllamaEmbeddings(
            model="nomic-embed-text",
            base_url=ollama_base_url(),
            client_kwargs={"timeout": model_http_timeout()},
        )

    def embed_documents(self, texts):
        try:
            return self.model.embed_documents([
                f"search_document: {text}" for text in texts
            ])
        except httpx.TimeoutException as error:
            raise TimeoutError("Embedding request exceeded its configured transport timeout.") from error

    def embed_query(self, text):
        try:
            return self.model.embed_query(f"search_query: {text}")
        except httpx.TimeoutException as error:
            raise TimeoutError("Embedding request exceeded its configured transport timeout.") from error
