from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from dotenv import load_dotenv
from config import config
import json


load_dotenv()
embedding = OpenAIEmbeddings(
    model = config["EMBEDDING_MODEL"]
)

db = Chroma(
    collection_name="security",
    persist_directory="./chromaStore",
    embedding_function=embedding
)

truth = {}
packages = ["flask", "requests", "pyyaml", "django", "cryptography"]
with open("./security_scan_results.json", "r") as f:
    truth = json.load(f)

def get_metrics(package: str, k:int) -> dict:
    documents = db.similarity_search(
        k=k,
        query=f"{package} security vulnerability",
        filter={"package": package}
    )

    retrieved_ids = []
    for doc in documents:
        retrieved_ids.append( doc.metadata.get("advisory_id") or doc.metadata.get("cve_id", "unknow") )
    total_relevant_ids = truth[package]
    relevant_retrieved_ids = [id for id in retrieved_ids if id in total_relevant_ids]
    precision = round(len(relevant_retrieved_ids) / len(retrieved_ids), 2) 
    recall = round(len(relevant_retrieved_ids) / len(total_relevant_ids), 2) 
    f1 = round( 2 * (precision * recall) / (precision + recall), 2)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

def evaluate():

    precision_k_3 = 0
    precision_k_5 = 0
    recall_k_3 = 0
    recall_k_5 = 0
    f1_3 = 0
    f1_5 = 0

    total_packages = len(packages)
    for package in packages:
        metrics3 = get_metrics(package, 3)
        metrics5 = get_metrics(package, 5)

        precision_k_3 += metrics3["precision"]
        precision_k_5 += metrics5["precision"]
       

        recall_k_3 += metrics3["recall"]
        recall_k_5 += metrics5["recall"]

        f1_3 += metrics3["f1"]
        f1_5 += metrics5["f1"]

    print("Metrics for K=3")
    print("-"*80)
    print("Total precision: ", round(precision_k_3 / total_packages, 2))
    print("Total recall: ", round(recall_k_3 / total_packages, 2))
    print("Total f1: ", round(f1_3 / total_packages , 2))
    print()
    print("*"*80)
    print()
    print("Metrics for K=5")
    print("-"*80)
    print("Total precision: ", round(precision_k_5 / total_packages, 2))
    print("Total recall: ", round(recall_k_5 / total_packages, 2))
    print("Total f1: ", round(f1_5 / total_packages , 2))

evaluate()
