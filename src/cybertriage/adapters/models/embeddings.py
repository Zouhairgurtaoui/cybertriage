from langchain_core.embeddings import Embeddings
from langchain_ollama import OllamaEmbeddings
from cybertriage.adapters.configuration.ollama_environment import ollama_base_url

class RunbookEmbeddings(Embeddings):
    def __init__(self):
        self.model = OllamaEmbeddings(
            model="nomic-embed-text",
            base_url=ollama_base_url(),
        )

    def embed_documents(self, texts):
        return self.model.embed_documents([
            f"search_document: {text}" for text in texts
        ])

    def embed_query(self, text):
        return self.model.embed_query(f"search_query: {text}")
