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

query = input("Ask a question: ")

results = db.similarity_search(query, k=3)

print("\n===== RETRIEVED EVIDENCE =====\n")

for i, doc in enumerate(results, start=1):
    print(f"Document {i}")
    print("-" * 60)
    print(doc.page_content[:1000])
    print()
    print("Source:", doc.metadata.get("source"))
    print("=" * 60)