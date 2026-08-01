from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

from embedding_config import EMBEDDING_MODEL_NAME


embeddings = HuggingFaceEmbeddings(
    model_name=EMBEDDING_MODEL_NAME
)


db = Chroma(
    persist_directory="./vector_db",
    embedding_function=embeddings
)


def retrieve_knowledge(query, k=3):

    results = db.similarity_search(
        query,
        k=k
    )


    evidence = []


    for doc in results:

        evidence.append(
            {
                "content": doc.page_content[:1500],
                "source": doc.metadata.get("source")
            }
        )


    return evidence